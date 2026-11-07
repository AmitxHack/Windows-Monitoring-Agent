
import platform
import psutil
from datetime import datetime

def display_system_info():
    print("=" * 55)
    print(" WINDOWS SERVICE & PROCESS MONITORING AGENT")
    print("=" * 55)

    print(f"Operating System : {platform.system()}")
    print(f"OS Version       : {platform.version()}")
    print(f"Machine          : {platform.machine()}")
    print(f"Python Version   : {platform.python_version()}")
    print(f"CPU Cores        : {psutil.cpu_count()}")
    print(f"RAM Total        : {round(psutil.virtual_memory().total / (1024**3), 2)} GB")
    print(f"Current Time     : {datetime.now()}")

    print("=" * 55)
    print("System information collected successfully.")

if __name__ == "__main__":
    display_system_info()
