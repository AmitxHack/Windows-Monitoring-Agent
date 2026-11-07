
import psutil
import time
import json

from datetime import datetime
from pathlib import Path


# Project configuration
PROJECT_ROOT = Path(__file__).resolve().parent.parent
LOG_DIR = PROJECT_ROOT / "logs"
LOG_FILE = LOG_DIR / "resource_alerts.jsonl"

POLL_INTERVAL = 2

CPU_THRESHOLD = 80.0
MEMORY_THRESHOLD = 10.0

# Total logical CPU cores
LOGICAL_CPU_COUNT = psutil.cpu_count(logical=True) or 1


def save_alert(resource, process_info, value, threshold):

    event = {
        "timestamp": datetime.now().astimezone().isoformat(),
        "event_type": "RESOURCE_THRESHOLD_EXCEEDED",
        "resource": resource,
        "observed_value": round(value, 2),
        "threshold": threshold,
        "process": process_info
    }

    with LOG_FILE.open("a", encoding="utf-8") as file:
        file.write(json.dumps(event) + "\n")


def collect_resource_data():

    results = []

    for proc in psutil.process_iter(
        ["pid", "ppid", "name", "exe", "create_time"]
    ):

        try:
            with proc.oneshot():

                info = proc.info

                # Collect raw CPU usage
                raw_cpu = proc.cpu_percent(interval=None)

                # Normalize CPU across logical processors
                normalized_cpu = raw_cpu / LOGICAL_CPU_COUNT

                # Collect memory usage
                memory = proc.memory_percent()
                memory_info = proc.memory_info()

                results.append({
                    "pid": info["pid"],
                    "ppid": info["ppid"],
                    "name": info["name"],
                    "exe_path": info["exe"],
                    "create_time": info["create_time"],

                    "cpu_percent": normalized_cpu,
                    "cpu_percent_raw": raw_cpu,

                    "memory_percent": memory,
                    "memory_mb": round(
                        memory_info.rss / (1024 * 1024), 2
                    )
                })

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return results


def start_monitoring():

    LOG_DIR.mkdir(parents=True, exist_ok=True)

    print("=" * 75)
    print(" CPU & MEMORY BEHAVIOR MONITORING")
    print("=" * 75)

    print(f"CPU Threshold: {CPU_THRESHOLD}%")
    print(f"Memory Threshold: {MEMORY_THRESHOLD}%")
    print(f"Logical CPU Cores: {LOGICAL_CPU_COUNT}")
    print(f"Polling Interval: {POLL_INTERVAL} seconds")

    print("\nInitializing CPU measurements...")

    # Prime CPU counters before taking measurements
    for proc in psutil.process_iter():

        try:
            proc.cpu_percent(interval=None)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    time.sleep(POLL_INTERVAL)

    active_alerts = set()

    print("\nMonitoring started. Press CTRL+C to stop.")
    print("-" * 75)

    try:

        while True:

            processes = collect_resource_data()

            current_alerts = set()

            for process in processes:

                # Exclude Windows System Idle Process
                if process["pid"] == 0:
                    continue

                identity = (
                    process["pid"],
                    round(process["create_time"], 3)
                )

                # CPU threshold check
                if process["cpu_percent"] >= CPU_THRESHOLD:

                    alert_key = identity + ("CPU",)
                    current_alerts.add(alert_key)

                    if alert_key not in active_alerts:

                        print(
                            f"[CPU ALERT] {process['name']} | "
                            f"PID: {process['pid']} | "
                            f"CPU: {process['cpu_percent']:.2f}% "
                            f"(Raw: {process['cpu_percent_raw']:.2f}%)"
                        )

                        save_alert(
                            "CPU",
                            process,
                            process["cpu_percent"],
                            CPU_THRESHOLD
                        )

                # Memory threshold check
                if process["memory_percent"] >= MEMORY_THRESHOLD:

                    alert_key = identity + ("MEMORY",)
                    current_alerts.add(alert_key)

                    if alert_key not in active_alerts:

                        print(
                            f"[MEMORY ALERT] {process['name']} | "
                            f"PID: {process['pid']} | "
                            f"RAM: {process['memory_percent']:.2f}%"
                        )

                        save_alert(
                            "MEMORY",
                            process,
                            process["memory_percent"],
                            MEMORY_THRESHOLD
                        )

            # Keep alerts active only while threshold is exceeded
            active_alerts = current_alerts

            time.sleep(POLL_INTERVAL)

    except KeyboardInterrupt:

        print("\nResource monitoring stopped.")
        print(f"Alerts saved to: {LOG_FILE}")


if __name__ == "__main__":
    start_monitoring()
