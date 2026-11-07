
import psutil
from datetime import datetime


def collect_processes():

    processes = []

    for process in psutil.process_iter(
        [
            "pid",
            "ppid",
            "name",
            "exe",
            "username",
            "create_time",
            "status",
            "memory_info"
        ]
    ):

        try:
            info = process.info

            memory = info.get("memory_info")

            process_data = {
                "pid": info.get("pid"),
                "ppid": info.get("ppid"),
                "name": info.get("name"),
                "exe_path": info.get("exe"),
                "username": info.get("username"),
                "create_time": info.get("create_time"),
                "status": info.get("status"),
                "memory_mb": (
                    round(memory.rss / (1024 * 1024), 2)
                    if memory else None
                )
            }

            processes.append(process_data)

        except (
            psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess
        ):
            continue

    return processes


def display_processes(processes):

    print("=" * 90)
    print(" WINDOWS PROCESS MONITORING ENGINE")
    print("=" * 90)

    print(f"Scan Time: {datetime.now()}")
    print(f"Total Processes: {len(processes)}")

    print("-" * 90)

    for process in processes:

        print(
            f"PID: {process['pid']} | "
            f"PPID: {process['ppid']} | "
            f"Name: {process['name']} | "
            f"Memory: {process['memory_mb']} MB"
        )

    print("=" * 90)


if __name__ == "__main__":

    process_list = collect_processes()

    display_processes(process_list)
