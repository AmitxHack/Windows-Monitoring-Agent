
import psutil
import time
import json

from datetime import datetime
from pathlib import Path


# Project root and event log location
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "process_events.jsonl"

POLL_INTERVAL = 2


def collect_snapshot():

    snapshot = {}

    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "username", "create_time"]
    ):

        try:
            info = proc.info

            pid = info.get("pid")
            create_time = info.get("create_time")

            if pid is None or create_time is None:
                continue

            # Include creation time to reduce PID reuse confusion
            process_key = (pid, round(create_time, 3))

            snapshot[process_key] = {
                "pid": pid,
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe_path": info.get("exe"),
                "username": info.get("username"),
                "create_time": create_time
            }

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return snapshot


def save_event(event_type, process_info):

    event = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "event_type": event_type,
        "process": process_info
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def display_event(event_type, process_info):

    print(
        f"[{datetime.now().strftime('%H:%M:%S')}] "
        f"[{event_type}] "
        f"PID: {process_info['pid']} | "
        f"Name: {process_info['name']} | "
        f"PPID: {process_info['ppid']}"
    )


def start_monitoring():

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 70)
    print(" REAL-TIME PROCESS MONITORING")
    print("=" * 70)

    print(f"Polling Interval: {POLL_INTERVAL} seconds")
    print(f"Event Log: {LOG_FILE}")
    print("\nCollecting initial process baseline...")

    previous_snapshot = collect_snapshot()

    print(f"Baseline Processes: {len(previous_snapshot)}")
    print("Monitoring started. Press CTRL+C to stop.")
    print("-" * 70)

    try:

        while True:

            time.sleep(POLL_INTERVAL)

            current_snapshot = collect_snapshot()

            previous_keys = set(previous_snapshot)
            current_keys = set(current_snapshot)

            # Detect newly observed processes
            new_processes = current_keys - previous_keys

            # Detect processes no longer present
            terminated_processes = previous_keys - current_keys

            for key in new_processes:

                process_info = current_snapshot[key]

                display_event("PROCESS_STARTED", process_info)
                save_event("PROCESS_STARTED", process_info)

            for key in terminated_processes:

                process_info = previous_snapshot[key]

                display_event("PROCESS_TERMINATED", process_info)
                save_event("PROCESS_TERMINATED", process_info)

            previous_snapshot = current_snapshot

    except KeyboardInterrupt:

        print("\nMonitoring stopped by user.")
        print("Process events saved successfully.")


if __name__ == "__main__":
    start_monitoring()
