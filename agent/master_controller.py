
import subprocess
import sys

from pathlib import Path
from datetime import datetime


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent
AGENT_DIR = PROJECT_ROOT / "agent"


# ==========================================
# MODULE DEFINITIONS
# ==========================================

PROCESS_MODULES = [
    "system_info.py",
    "process_monitor.py",
    "process_tree.py",
    "unauthorized_process_detector.py"
]

SERVICE_MODULES = [
    "service_audit.py",
    "service_change_monitor.py",
    "service_security_analyzer.py"
]

REPORT_MODULES = [
    "central_alert_engine.py",
    "pdf_report_generator.py"
]


# ==========================================
# DISPLAY BANNER
# ==========================================

def display_banner():

    print("\n" + "=" * 75)

    print(" WINDOWS SERVICE & PROCESS MONITORING AGENT ")

    print("=" * 75)

    print("Master Monitoring Controller")

    print(f"Python Version: {sys.version.split()[0]}")

    print(f"Scan Started: {datetime.now().astimezone().isoformat()}")

    print("=" * 75)


# ==========================================
# EXECUTE MODULE
# ==========================================

def execute_module(module_name):

    module_path = AGENT_DIR / module_name

    print("\n" + "-" * 75)

    print(f"EXECUTING MODULE: {module_name}")

    print("-" * 75)

    if not module_path.is_file():

        print(f"[SKIPPED] Module not found: {module_path}")

        return False

    try:

        result = subprocess.run(
            [sys.executable, str(module_path)],
            cwd=str(PROJECT_ROOT),
            check=False
        )

        if result.returncode == 0:

            print(f"\n[SUCCESS] {module_name}")

            return True

        print(
            f"\n[FAILED] {module_name} "
            f"| Exit Code: {result.returncode}"
        )

        return False

    except OSError as error:

        print(f"[ERROR] {module_name}: {error}")

        return False


# ==========================================
# EXECUTE MODULE GROUP
# ==========================================

def execute_group(modules, group_name):

    print("\n" + "=" * 75)

    print(f"STARTING {group_name}")

    print("=" * 75)

    results = []

    for module in modules:

        status = execute_module(module)

        results.append((module, status))

    return results


# ==========================================
# DISPLAY EXECUTION SUMMARY
# ==========================================

def display_summary(results):

    successful = sum(
        1 for _, status in results if status
    )

    failed = len(results) - successful

    print("\n" + "=" * 75)

    print("MASTER CONTROLLER EXECUTION SUMMARY")

    print("=" * 75)

    for module, status in results:

        result = "SUCCESS" if status else "FAILED / SKIPPED"

        print(f"{module:<40} {result}")

    print("-" * 75)

    print(f"Total Modules : {len(results)}")

    print(f"Successful    : {successful}")

    print(f"Failed        : {failed}")

    print("=" * 75)


# ==========================================
# MAIN MENU
# ==========================================

def display_menu():

    print("\nSELECT MONITORING OPTION")

    print("-" * 50)

    print("1. Full Security Scan")

    print("2. Process Security Scan")

    print("3. Windows Service Security Scan")

    print("4. Generate Central JSON + PDF Reports")

    print("5. Exit")

    print("-" * 50)


# ==========================================
# MAIN CONTROLLER
# ==========================================

def main():

    if sys.platform != "win32":

        print("This project requires Windows.")

        return

    display_banner()

    while True:

        display_menu()

        choice = input("\nEnter your choice: ").strip()

        results = []

        if choice == "1":

            results.extend(
                execute_group(
                    PROCESS_MODULES,
                    "PROCESS SECURITY SCAN"
                )
            )

            results.extend(
                execute_group(
                    SERVICE_MODULES,
                    "SERVICE SECURITY SCAN"
                )
            )

            # Generate report after scans
            results.extend(
                execute_group(
                    REPORT_MODULES,
                    "CENTRAL JSON + PDF REPORT GENERATION"
                )
            )

            display_summary(results)

        elif choice == "2":

            results = execute_group(
                PROCESS_MODULES,
                "PROCESS SECURITY SCAN"
            )

            results.extend(
                execute_group(
                    REPORT_MODULES,
                    "CENTRAL JSON + PDF REPORT GENERATION"
                )
            )

            display_summary(results)

        elif choice == "3":

            results = execute_group(
                SERVICE_MODULES,
                "SERVICE SECURITY SCAN"
            )

            results.extend(
                execute_group(
                    REPORT_MODULES,
                    "CENTRAL JSON + PDF REPORT GENERATION"
                )
            )

            display_summary(results)

        elif choice == "4":

            results = execute_group(
                REPORT_MODULES,
                "CENTRAL JSON + PDF REPORT GENERATION"
            )

            display_summary(results)

        elif choice == "5":

            print("\nMaster Controller stopped.")

            break

        else:

            print("\nInvalid choice. Please select 1-5.")


if __name__ == "__main__":

    main()
