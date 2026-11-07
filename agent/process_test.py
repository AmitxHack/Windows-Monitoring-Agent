
import psutil

print("\nACTIVE WINDOWS PROCESSES")
print("-" * 75)

for process in psutil.process_iter(
    ['pid', 'ppid', 'name', 'username']
):
    try:
        info = process.info

        print(
            f"PID: {info['pid']} | "
            f"PPID: {info['ppid']} | "
            f"Name: {info['name']} | "
            f"User: {info['username']}"
        )

    except (psutil.NoSuchProcess,
            psutil.AccessDenied,
            psutil.ZombieProcess):
        continue
