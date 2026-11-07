
import psutil
import json
import os

from datetime import datetime
from pathlib import Path


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"
REPORT_DIR = PROJECT_ROOT / "reports"

ALLOWLIST_FILE = CONFIG_DIR / "process_allowlist.json"
REPORT_FILE = REPORT_DIR / "unauthorized_process_report.json"

SUSPICIOUS_LOCATIONS = [
    "\\appdata\\local\\temp\\",
    "\\windows\\temp\\",
    "\\users\\public\\",
    "\\downloads\\"
]


# ==========================================
# INITIALIZE PROCESS ALLOWLIST
# ==========================================

def initialize_allowlist():

    CONFIG_DIR.mkdir(parents=True, exist_ok=True)

    if not ALLOWLIST_FILE.exists():

        default_config = {
            "allowed_process_names": [],
            "blocked_process_names": []
        }

        with ALLOWLIST_FILE.open(
            "w",
            encoding="utf-8"
        ) as file:

            json.dump(
                default_config,
                file,
                indent=4
            )


def load_allowlist():

    initialize_allowlist()

    with ALLOWLIST_FILE.open(
        "r",
        encoding="utf-8"
    ) as file:

        config = json.load(file)

    return {
        "allowed": {
            name.lower()
            for name in config.get("allowed_process_names", [])
        },

        "blocked": {
            name.lower()
            for name in config.get("blocked_process_names", [])
        }
    }


# ==========================================
# COLLECT ACTIVE PROCESSES
# ==========================================

def collect_processes():

    processes = []

    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "create_time"]
    ):

        try:

            info = proc.info

            if info["pid"] == 0:
                continue

            processes.append({

                "pid": info["pid"],
                "ppid": info["ppid"],
                "name": info["name"],
                "exe_path": info["exe"],
                "username": info["username"],
                "create_time": info["create_time"]

            })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):

            continue

    return processes


# ==========================================
# PROCESS SECURITY ANALYSIS
# ==========================================


def analyze_process(process, allowlist):

    findings = []

    pid = process.get("pid")
    name = (process.get("name") or "").lower()
    exe_path = process.get("exe_path") or ""

    normalized_path = exe_path.lower()

    # Special Windows System process
    if pid == 4 and name == "system":
        return findings

    # Process name unavailable
    if not name:
        return findings

    # Blocklist check
    if name in allowlist["blocked"]:

        findings.append({
            "rule": "BLOCKLIST_MATCH",
            "severity": "HIGH",
            "reason": "Process matches configured blocklist."
        })

    # Allowlist check
    elif name not in allowlist["allowed"]:

        findings.append({
            "rule": "UNKNOWN_PROCESS",
            "severity": "INFO",
            "reason": (
                "Process is not present in the configured "
                "allowlist. Verify its identity."
            )
        })

    # Check suspicious execution location
    if exe_path and any(
        location in normalized_path
        for location in SUSPICIOUS_LOCATIONS
    ):

        findings.append({
            "rule": "SUSPICIOUS_EXECUTION_LOCATION",
            "severity": "HIGH",
            "reason": (
                "Executable is located in a temporary "
                "or user-writable directory."
            )
        })

    # Missing path is not automatically suspicious
    if not exe_path:

        findings.append({
            "rule": "EXECUTABLE_PATH_UNAVAILABLE",
            "severity": "INFO",
            "reason": (
                "Executable path is unavailable. "
                "Check permissions and process type."
            )
        })

    return findings



# ==========================================
# GENERATE PROCESS SECURITY REPORT
# ==========================================

def generate_report(processes, allowlist):

    results = []

    for process in processes:

        findings = analyze_process(process, allowlist)

        if findings:

            results.append({

                "process": process,
                "findings": findings,

                "risk_status": "REVIEW_REQUIRED"

            })

    report = {

        "scan_timestamp": datetime.now().astimezone().isoformat(),

        "total_processes": len(processes),

        "processes_requiring_review": len(results),

        "processes": results

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


# ==========================================
# DISPLAY RESULTS
# ==========================================

def display_report(report):

    print("=" * 85)
    print(" UNAUTHORIZED PROCESS DETECTION ENGINE")
    print("=" * 85)

    print(f"Scan Time: {report['scan_timestamp']}")

    print(
        f"Total Processes: {report['total_processes']}"
    )

    print(
        f"Processes Requiring Review: "
        f"{report['processes_requiring_review']}"
    )

    print("-" * 85)

    for item in report["processes"]:

        process = item["process"]

        for finding in item["findings"]:

            print(
                f"\n[{finding['severity']}] "
                f"{finding['rule']}"
            )

            print(
                f"Process: {process['name']} | "
                f"PID: {process['pid']} | "
                f"PPID: {process['ppid']}"
            )

            print(f"Path: {process['exe_path']}")

            print(f"Reason: {finding['reason']}")

    print("\n" + "=" * 85)

    print(f"Report saved: {REPORT_FILE}")


# ==========================================
# MAIN
# ==========================================

def main():

    if os.name != "nt":

        print("This module requires Windows.")
        return

    print("Initializing process detection engine...")

    allowlist = load_allowlist()

    print("Collecting active processes...")

    processes = collect_processes()

    print("Analyzing process security...")

    report = generate_report(
        processes,
        allowlist
    )

    display_report(report)


if __name__ == "__main__":

    main()
