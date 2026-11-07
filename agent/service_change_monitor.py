
import psutil
import json

from datetime import datetime
from pathlib import Path


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

CONFIG_DIR = PROJECT_ROOT / "config"
LOG_DIR = PROJECT_ROOT / "logs"

BASELINE_FILE = CONFIG_DIR / "service_baseline.json"
EVENT_LOG = LOG_DIR / "service_changes.jsonl"


# ==========================================
# FIELDS USED FOR COMPARISON
# ==========================================

TRACKED_FIELDS = [
    "display_name",
    "start_type",
    "username",
    "binary_path",
    "description"
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
        RuntimeError,
        FileNotFoundError
    ):

        return default

    except Exception:

        return default


# ==========================================
# COLLECT WINDOWS SERVICES
# ==========================================

def collect_services():

    services = {}

    print("\nCollecting Windows services...\n")

    for service in psutil.win_service_iter():

        try:

            # Get service name safely
            name = safe_service_value(service, "name")

            if not name:
                continue

            # Collect properties individually
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

            services[name] = service_data

        except Exception as error:

            print(
                f"[WARNING] Service collection failed: {error}"
            )

            continue

    return services


# ==========================================
# SAVE JSON DATA
# ==========================================

def save_json(path, data):

    path.parent.mkdir(parents=True, exist_ok=True)

    with path.open("w", encoding="utf-8") as file:

        json.dump(
            data,
            file,
            indent=4,
            ensure_ascii=False
        )


# ==========================================
# SAVE DETECTED EVENTS
# ==========================================

def save_event(event_type, service_name, details):

    event = {

        "timestamp": datetime.now().astimezone().isoformat(),

        "event_type": event_type,

        "service_name": service_name,

        "details": details

    }

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    with EVENT_LOG.open("a", encoding="utf-8") as file:

        file.write(
            json.dumps(event, ensure_ascii=False) + "\n"
        )


# ==========================================
# COMPARE PREVIOUS AND CURRENT SERVICES
# ==========================================

def compare_services(previous, current):

    previous_names = set(previous)

    current_names = set(current)

    added = current_names - previous_names

    removed = previous_names - current_names

    common = previous_names & current_names

    events = []

    # Detect newly registered services

    for name in sorted(added):

        events.append({

            "type": "NEW_SERVICE",

            "name": name,

            "details": current[name]

        })

    # Detect removed services

    for name in sorted(removed):

        events.append({

            "type": "SERVICE_REMOVED",

            "name": name,

            "details": previous[name]

        })

    # Detect configuration changes

    for name in sorted(common):

        changes = {}

        for field in TRACKED_FIELDS:

            old_value = previous[name].get(field)

            new_value = current[name].get(field)

            if old_value != new_value:

                changes[field] = {

                    "old": old_value,

                    "new": new_value

                }

        if changes:

            events.append({

                "type": "SERVICE_CONFIGURATION_CHANGED",

                "name": name,

                "details": changes

            })

    return events


# ==========================================
# START SERVICE AUDIT
# ==========================================

def start_audit():

    print("=" * 75)

    print(" WINDOWS SERVICE CHANGE DETECTION")

    print("=" * 75)

    current_services = collect_services()

    print(
        f"Current Services: {len(current_services)}"
    )

    # First run: Create initial baseline

    if not BASELINE_FILE.exists():

        save_json(
            BASELINE_FILE,
            current_services
        )

        print("\nInitial service baseline created.")

        print(f"Baseline: {BASELINE_FILE}")

        return

    # Load previous baseline

    try:

        with BASELINE_FILE.open(
            "r",
            encoding="utf-8"
        ) as file:

            previous_services = json.load(file)

        if not isinstance(previous_services, dict):

            raise ValueError(
                "Invalid service baseline format."
            )

    except (json.JSONDecodeError, OSError, ValueError) as error:

        print(f"\n[ERROR] Unable to load baseline: {error}")

        print("Existing baseline was not modified.")

        return

    # Compare previous and current services

    events = compare_services(
        previous_services,
        current_services
    )

    # Display detected changes

    if not events:

        print("\nNo service configuration changes detected.")

    else:

        print(
            f"\nChanges Detected: {len(events)}"
        )

        for event in events:

            print(

                f"\n[{event['type']}] "
                f"Service: {event['name']}"

            )

            print(
                f"Details: {event['details']}"
            )

            save_event(

                event["type"],

                event["name"],

                event["details"]

            )

    # Update baseline

    save_json(
        BASELINE_FILE,
        current_services
    )

    print("\nService baseline updated.")

    print(f"Event Log: {EVENT_LOG}")


# ==========================================
# MAIN EXECUTION
# ==========================================

if __name__ == "__main__":

    start_audit()
