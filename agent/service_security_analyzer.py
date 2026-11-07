
import os
import re
import json
import subprocess
import psutil

from datetime import datetime
from pathlib import Path


# ==================================================
# PROJECT CONFIGURATION
# ==================================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORT_DIR = PROJECT_ROOT / "reports"
REPORT_FILE = REPORT_DIR / "service_security_report.json"

USER_WRITABLE_LOCATIONS = [
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
    "\\users\\public\\"
]

SIGNATURE_CACHE = {}


# ==================================================
# SAFE SERVICE PROPERTY RETRIEVAL
# ==================================================

def safe_service_value(service, method_name, default=None):

    try:

        method = getattr(service, method_name)

        return method()

    except (
        psutil.Error,
        OSError,
        AttributeError,
        RuntimeError
    ):

        return default

    except Exception:

        return default


# ==================================================
# EXECUTABLE PATH EXTRACTION
# ==================================================

def extract_executable_path(binary_path):

    if not binary_path:

        return None, False

    binary_path = os.path.expandvars(
        binary_path.strip()
    )

    # Handle quoted executable paths

    if binary_path.startswith('"'):

        match = re.match(
            r'^"([^"]+\.exe)"',
            binary_path,
            re.IGNORECASE
        )

        if match:

            return match.group(1), False

    # Handle unquoted executable paths

    match = re.match(
        r"^\s*(.+?\.exe)(?:\s|$)",
        binary_path,
        re.IGNORECASE
    )

    if match:

        executable = match.group(1).strip()

        unquoted = " " in executable

        return executable, unquoted

    # Path could not be parsed confidently

    return None, False


# ==================================================
# DIGITAL SIGNATURE VERIFICATION
# ==================================================

def check_digital_signature(executable_path):

    if executable_path in SIGNATURE_CACHE:

        return SIGNATURE_CACHE[executable_path]

    result = {

        "status": "UNKNOWN",

        "signer": None

    }

    # Escape single quotes for PowerShell

    escaped_path = executable_path.replace("'", "''")

    command = (
        f"$s = Get-AuthenticodeSignature "
        f"-LiteralPath '{escaped_path}'; "
        f"[PSCustomObject]@{{"
        f"Status=$s.Status.ToString(); "
        f"Signer=$s.SignerCertificate.Subject"
        f"}} | ConvertTo-Json -Compress"
    )

    try:

        output = subprocess.run(

            [
                "powershell.exe",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                command
            ],

            capture_output=True,

            text=True,

            timeout=15

        )

        if output.returncode == 0 and output.stdout.strip():

            signature = json.loads(
                output.stdout.strip().lstrip("\ufeff")
            )

            result = {

                "status": signature.get(
                    "Status", "UNKNOWN"
                ),

                "signer": signature.get("Signer")

            }

    except (
        subprocess.TimeoutExpired,
        subprocess.SubprocessError,
        OSError,
        json.JSONDecodeError
    ):

        pass

    SIGNATURE_CACHE[executable_path] = result

    return result


# ==================================================
# SERVICE SECURITY ANALYSIS
# ==================================================

def analyze_service(service):

    findings = []

    executable = None

    signature = {
        "status": "UNKNOWN",
        "signer": None
    }

    binary_path = service.get("binary_path") or ""

    executable, is_unquoted = extract_executable_path(
        binary_path
    )

    # Check whether executable path can be extracted

    if not executable:

        findings.append({

            "rule": "BINARY_PATH_UNRESOLVED",

            "severity": "INFO",

            "reason": (
                "Could not confidently extract executable path."
            )

        })

        return {

            "findings": findings,

            "executable_path": None,

            "signature": signature

        }

    # Normalize Windows environment paths

    if executable.lower().startswith("\\systemroot\\"):

        executable = os.environ.get(
            "SystemRoot",
            r"C:\Windows"
        ) + executable[len("\\SystemRoot"):]

    executable_path = Path(executable)

    # Check unquoted service path

    if is_unquoted:

        findings.append({

            "rule": "UNQUOTED_SERVICE_PATH",

            "severity": "HIGH",

            "reason": (
                "Service executable path contains spaces "
                "without surrounding quotes. Investigate "
                "Windows executable path resolution."
            )

        })

    # Check executable existence

    try:

        exists = executable_path.is_file()

    except OSError:

        exists = False

    if not exists:

        findings.append({

            "rule": "BINARY_NOT_FOUND",

            "severity": "MEDIUM",

            "reason": (
                "Service executable file could not be found."
            )

        })

        return {

            "findings": findings,

            "executable_path": str(executable_path),

            "signature": signature

        }

    # Check user-writable directory indicators

    normalized_path = str(executable_path).lower().replace(
        "/", "\\"
    )

    if any(

        location in normalized_path

        for location in USER_WRITABLE_LOCATIONS

    ):

        findings.append({

            "rule": "USER_WRITABLE_LOCATION",

            "severity": "HIGH",

            "reason": (
                "Executable is located in a directory "
                "commonly writable by standard users."
            )

        })

    # Verify digital signature

    signature = check_digital_signature(
        str(executable_path)
    )

    signature_status = signature["status"]

    if signature_status == "NotSigned":

        findings.append({

            "rule": "UNSIGNED_EXECUTABLE",

            "severity": "MEDIUM",

            "reason": (
                "Executable has no Authenticode signature. "
                "Verify its origin and integrity."
            )

        })

    elif signature_status in (
        "HashMismatch",
        "NotTrusted"
    ):

        findings.append({

            "rule": "SIGNATURE_VALIDATION_FAILED",

            "severity": "HIGH",

            "reason": (
                f"Authenticode signature status: "
                f"{signature_status}"
            )

        })

    return {

        "findings": findings,

        "executable_path": str(executable_path),

        "signature": signature

    }


# ==================================================
# COLLECT WINDOWS SERVICES
# ==================================================

def collect_services():

    services = []

    print("Collecting Windows services...\n")

    for service in psutil.win_service_iter():

        try:

            # Get service name safely

            name = safe_service_value(
                service, "name"
            )

            if not name:

                continue

            # Collect individual properties safely

            service_data = {

                "name": name,

                "display_name": safe_service_value(
                    service, "display_name"
                ),

                "status": safe_service_value(
                    service, "status"
                ),

                "start_type": safe_service_value(
                    service, "start_type"
                ),

                "username": safe_service_value(
                    service, "username"
                ),

                "binary_path": safe_service_value(
                    service, "binpath"
                ),

                "pid": safe_service_value(
                    service, "pid"
                ),

                "description": safe_service_value(
                    service, "description"
                )

            }

            services.append(service_data)

        except Exception as error:

            print(
                f"[WARNING] Service collection failed: {error}"
            )

            continue

    return services


# ==================================================
# GENERATE SECURITY REPORT
# ==================================================

def generate_report(services):

    results = []

    for service in services:

        analysis = analyze_service(service)

        findings = analysis["findings"]

        results.append({

            "service": service,

            "executable_path": analysis["executable_path"],

            "signature": analysis["signature"],

            "findings": findings,

            "risk_status": (

                "REVIEW_REQUIRED"

                if findings

                else "NO_RULE_MATCH"

            )

        })

    report = {

        "scan_timestamp": datetime.now().astimezone().isoformat(),

        "total_services": len(results),

        "services_requiring_review": sum(

            1 for item in results

            if item["findings"]

        ),

        "services": results

    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with REPORT_FILE.open(
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(

            report,

            file,

            indent=4,

            ensure_ascii=False

        )

    return report


# ==================================================
# DISPLAY RESULTS
# ==================================================

def display_report(report):

    print("=" * 85)

    print(" WINDOWS SERVICE SECURITY ANALYZER")

    print("=" * 85)

    print(
        f"Scan Time: {report['scan_timestamp']}"
    )

    print(
        f"Total Services: {report['total_services']}"
    )

    print(
        f"Services Requiring Review: "
        f"{report['services_requiring_review']}"
    )

    print("-" * 85)

    for item in report["services"]:

        service = item["service"]

        if not item["findings"]:

            continue

        print(
            f"\nService: {service['name']}"
        )

        print(
            f"Executable: {item['executable_path']}"
        )

        print(
            f"Signature: {item['signature']['status']}"
        )

        for finding in item["findings"]:

            print(

                f"  [{finding['severity']}] "
                f"{finding['rule']}"

            )

            print(
                f"  Reason: {finding['reason']}"
            )

    print("\n" + "=" * 85)

    print(
        f"Report saved: {REPORT_FILE}"
    )


# ==================================================
# MAIN EXECUTION
# ==================================================

def main():

    if os.name != "nt":

        print("This analyzer requires Windows.")

        return

    print("Collecting Windows services...")

    services = collect_services()

    print(
        f"Collected Services: {len(services)}"
    )

    print(
        "\nAnalyzing service security configurations..."
    )

    report = generate_report(services)

    display_report(report)


if __name__ == "__main__":

    main()
