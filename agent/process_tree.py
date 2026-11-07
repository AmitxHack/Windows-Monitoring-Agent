
from process_monitor import collect_processes


def analyze_process_tree(processes):

    process_map = {
        process["pid"]: process
        for process in processes
    }

    relationships = []

    for process in processes:

        parent_pid = process["ppid"]

        parent = process_map.get(parent_pid)

        parent_name = (
            parent["name"]
            if parent else "Not Available"
        )

        relationships.append({
            "pid": process["pid"],
            "ppid": parent_pid,
            "process_name": process["name"],
            "parent_name": parent_name
        })

    return relationships


def display_relationships(relationships):

    print("\nPARENT-CHILD PROCESS RELATIONSHIPS")
    print("=" * 85)

    for item in relationships:

        print(
            f"{item['parent_name']} "
            f"(PPID: {item['ppid']})"
            f" ---> "
            f"{item['process_name']} "
            f"(PID: {item['pid']})"
        )

    print("=" * 85)


if __name__ == "__main__":

    processes = collect_processes()

    relationships = analyze_process_tree(processes)

    display_relationships(relationships)
