
import psutil
import json

from datetime import datetime
from pathlib import Path


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LOG_DIR = PROJECT_ROOT / "logs"
REPORT_DIR = PROJECT_ROOT / "reports"

REPORT_FILE = REPORT_DIR / "service_audit.json"


# ==========================================
# SUSPICIOUS SERVICE LOCATIONS
# ==========================================

USER_WRITABLE_LOCATIONS = [
    "\\users\\",
    "\\appdata\\",
    "\\temp\\",
    "\\downloads\\",
    "\\desktop\\",
    "%temp%"
]


# ==========================================
# SAFE SERVICE PROPERTY RETRIEVAL
# ==========================================

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


# ==========================================
# COLLECT WINDOWS SERVICES
# ==========================================

def collect_services():

    services = []

    print("Collecting Windows services...\n")

    for service in psutil.win_service_iter():

        try:

            # Retrieve service name safely
            name = safe_service_value(service, "name")

            if not name:
                continue

            # Retrieve individual properties safely
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
                f"[WARNING] Unable to collect service: {error}"
            )

            continue

    return services


# ==========================================
# ANALYZE WINDOWS SERVICES
# ==========================================

def analyze_service(service):

    findings = []

    binary_path = service.get("binary_path") or ""

    normalized_path = binary_path.lower().replace("/", "\\")

    # Check for missing executable configuration

    if not binary_path.strip():

        findings.append({

            "rule": "MISSING_BINARY_PATH",

            "severity": "MEDIUM",

            "reason": (
                "Service binary path is unavailable or empty."
            )

        })

    # Check for unusual executable locations

    elif any(
        location in normalized_path
        for location in USER_WRITABLE_LOCATIONS
    ):

        findings.append({

            "rule": "USER_WRITABLE_PATH",

            "severity": "HIGH",

            "reason": (
                "Service executable path contains a "
                "user-writable or temporary directory."
            )

        })

    return findings


# ==========================================
# AUDIT ALL SERVICES
# ==========================================

def audit_services(services):

    audit_results = []

    for service in services:

        findings = analyze_service(service)

        result = {

            "service": service,

            "findings": findings,

            "risk_status": (
                "REVIEW_REQUIRED"
                if findings else "NO_RULE_MATCH"
            )

        }

        audit_results.append(result)

    return audit_results


# ==========================================
# SAVE JSON REPORT
# ==========================================

def save_report(results):

    REPORT_DIR.mkdir(parents=True, exist_ok=True)

    report = {

        "scan_timestamp": datetime.now().astimezone().isoformat(),

        "total_services": len(results),

        "services_with_findings": sum(
            1 for item in results if item["findings"]
        ),

        "services": results

    }

    with REPORT_FILE.open("w", encoding="utf-8") as file:

        json.dump(
            report,
            file,
            indent=4,
            ensure_ascii=False
        )

    return report


# ==========================================
# DISPLAY RESULTS
# ==========================================

def display_results(report):

    print("=" * 85)

    print(" WINDOWS SERVICE AUDITING ENGINE")

    print("=" * 85)

    print(f"Scan Time: {report['scan_timestamp']}")

    print(f"Total Services: {report['total_services']}")

    print(
        f"Services Requiring Review: "
        f"{report['services_with_findings']}"
    )

    print("-" * 85)

    for item in report["services"]:

        service = item["service"]

        print(

            f"Name: {service['name']} | "
            f"Status: {service['status']} | "
            f"Startup: {service['start_type']}"

        )

        if item["findings"]:

            for finding in item["findings"]:

                print(

                    f"  [REVIEW] {finding['rule']} | "
                    f"Severity: {finding['severity']}"

                )

    print("=" * 85)

    print(f"Report saved: {REPORT_FILE}")


# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":

    services = collect_services()

    results = audit_services(services)

    report = save_report(results)

    display_results(report)
