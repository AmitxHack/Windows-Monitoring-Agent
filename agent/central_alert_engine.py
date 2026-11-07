
import json

from datetime import datetime
from pathlib import Path
from collections import Counter


# ==========================================
# PROJECT CONFIGURATION
# ==========================================

PROJECT_ROOT = Path(__file__).resolve().parent.parent

REPORT_DIR = PROJECT_ROOT / "reports"
LOG_DIR = PROJECT_ROOT / "logs"

OUTPUT_FILE = REPORT_DIR / "central_alert_report.json"

JSON_REPORTS = [
    REPORT_DIR / "unauthorized_process_report.json",
    REPORT_DIR / "service_security_report.json"
]

JSONL_LOGS = [
    LOG_DIR / "resource_alerts.jsonl",
    LOG_DIR / "service_changes.jsonl"
]

PROCESS_EVENT_LOG = LOG_DIR / "process_events.jsonl"


# ==========================================
# SEVERITY NORMALIZATION
# ==========================================

def normalize_severity(severity):

    severity = str(severity or "INFO").upper()

    allowed = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    if severity not in allowed:
        return "INFO"

    return severity


# ==========================================
# JSON REPORT LOADER
# ==========================================

def load_json_report(file_path):

    if not file_path.exists():
        print(f"[SKIPPED] Missing report: {file_path.name}")
        return None

    try:

        with file_path.open("r", encoding="utf-8") as file:
            data = json.load(file)

        print(f"[LOADED] {file_path.name}")

        return data

    except (json.JSONDecodeError, OSError) as error:

        print(f"[ERROR] {file_path.name}: {error}")

        return None


# ==========================================
# EXTRACT FINDINGS RECURSIVELY
# ==========================================

def extract_findings(data, source):

    findings = []

    def walk(node, entity=None, timestamp=None):

        if isinstance(node, dict):

            current_entity = (
                node.get("process")
                or node.get("service")
                or entity
            )

            current_timestamp = (
                node.get("scan_timestamp")
                or node.get("timestamp")
                or timestamp
            )

            node_findings = node.get("findings", [])

            if isinstance(node_findings, list):

                for finding in node_findings:

                    if not isinstance(finding, dict):
                        continue

                    alert = {

                        "source": source,

                        "timestamp": current_timestamp,

                        "rule": finding.get(
                            "rule", "UNKNOWN_RULE"
                        ),

                        "severity": normalize_severity(
                            finding.get("severity")
                        ),

                        "reason": finding.get(
                            "reason", "No reason provided"
                        ),

                        "asset": current_entity

                    }

                    findings.append(alert)

            for key, value in node.items():

                if key == "findings":
                    continue

                walk(
                    value,
                    current_entity,
                    current_timestamp
                )

        elif isinstance(node, list):

            for item in node:

                walk(item, entity, timestamp)

    walk(data)

    return findings


# ==========================================
# JSONL EVENT LOADER
# ==========================================

def load_jsonl(file_path):

    events = []

    if not file_path.exists():
        print(f"[SKIPPED] Missing log: {file_path.name}")
        return events

    try:

        with file_path.open("r", encoding="utf-8") as file:

            for line_number, line in enumerate(file, 1):

                if not line.strip():
                    continue

                try:

                    events.append(json.loads(line))

                except json.JSONDecodeError:

                    print(
                        f"[WARNING] Invalid JSON in "
                        f"{file_path.name}, line {line_number}"
                    )

        print(f"[LOADED] {file_path.name}: {len(events)} events")

    except OSError as error:

        print(f"[ERROR] {file_path.name}: {error}")

    return events


# ==========================================
# RESOURCE ALERT NORMALIZATION
# ==========================================

def process_resource_events(events):

    alerts = []

    for event in events:

        if event.get("event_type") != "RESOURCE_THRESHOLD_EXCEEDED":
            continue

        observed = event.get("observed_value", 0)
        threshold = event.get("threshold", 0)

        try:

            observed = float(observed)
            threshold = float(threshold)

        except (TypeError, ValueError):

            observed = 0
            threshold = 0

        severity = (
            "HIGH"
            if threshold > 0 and observed >= threshold * 1.5
            else "MEDIUM"
        )

        alerts.append({

            "source": "resource_monitor",

            "timestamp": event.get("timestamp"),

            "rule": event.get(
                "event_type", "RESOURCE_ALERT"
            ),

            "severity": severity,

            "reason": (
                f"{event.get('resource')} threshold exceeded. "
                f"Observed: {observed}, Threshold: {threshold}"
            ),

            "asset": event.get("process"),

            "resource": event.get("resource"),

            "observed_value": observed,

            "threshold": threshold

        })

    return alerts


# ==========================================
# SERVICE CHANGE NORMALIZATION
# ==========================================

def process_service_changes(events):

    alerts = []

    for event in events:

        event_type = str(
            event.get("event_type", "")
        ).upper()

        if not event_type:
            continue

        alerts.append({

            "source": "service_change_monitor",

            "timestamp": event.get("timestamp"),

            "rule": event_type,

            "severity": "MEDIUM",

            "reason": "Windows service configuration change detected.",

            "asset": event.get("service")

        })

    return alerts


# ==========================================
# PROCESS EVENT STATISTICS
# ==========================================

def process_event_statistics():

    events = load_jsonl(PROCESS_EVENT_LOG)

    event_counts = Counter(
        event.get("event_type", "UNKNOWN")
        for event in events
    )

    return {

        "total_events": len(events),

        "process_started": event_counts.get(
            "PROCESS_STARTED", 0
        ),

        "process_terminated": event_counts.get(
            "PROCESS_TERMINATED", 0
        )

    }


# ==========================================
# DUPLICATE ALERT FILTER
# ==========================================

def remove_duplicates(alerts):

    unique_alerts = []

    seen = set()

    for alert in alerts:

        asset = alert.get("asset") or {}

        if not isinstance(asset, dict):
            asset = {"name": str(asset)}

        key = (

            alert.get("source"),

            alert.get("rule"),

            alert.get("timestamp"),

            asset.get("pid"),

            asset.get("name"),

            asset.get("service_name")

        )

        if key not in seen:

            seen.add(key)

            unique_alerts.append(alert)

    return unique_alerts


# ==========================================
# GENERATE CENTRAL REPORT
# ==========================================

def generate_central_report():

    all_alerts = []

    print("\nCollecting security reports...")

    # Load JSON reports
    for report_file in JSON_REPORTS:

        data = load_json_report(report_file)

        if data:

            findings = extract_findings(
                data,
                report_file.stem
            )

            all_alerts.extend(findings)

    # Load resource events
    resource_events = load_jsonl(
        JSONL_LOGS[0]
    )

    all_alerts.extend(
        process_resource_events(resource_events)
    )

    # Load service changes
    service_events = load_jsonl(
        JSONL_LOGS[1]
    )

    all_alerts.extend(
        process_service_changes(service_events)
    )

    # Remove duplicates
    unique_alerts = remove_duplicates(all_alerts)

    # Severity summary
    severity_counts = Counter(
        alert["severity"]
        for alert in unique_alerts
    )

    # Source summary
    source_counts = Counter(
        alert["source"]
        for alert in unique_alerts
    )

    # Final report
    report = {

        "report_timestamp": datetime.now().astimezone().isoformat(),

        "project": "Windows Service & Process Monitoring Agent",

        "summary": {

            "total_alerts": len(unique_alerts),

            "critical": severity_counts.get("CRITICAL", 0),

            "high": severity_counts.get("HIGH", 0),

            "medium": severity_counts.get("MEDIUM", 0),

            "low": severity_counts.get("LOW", 0),

            "info": severity_counts.get("INFO", 0)

        },

        "source_summary": dict(source_counts),

        "process_activity": process_event_statistics(),

        "alerts": unique_alerts

    }

    REPORT_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    with OUTPUT_FILE.open(
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
# DISPLAY CENTRAL DASHBOARD
# ==========================================

def display_report(report):

    summary = report["summary"]

    print("\n" + "=" * 75)

    print(" WINDOWS CENTRAL SECURITY ALERT ENGINE ")

    print("=" * 75)

    print(f"Report Time: {report['report_timestamp']}")

    print(f"Total Alerts: {summary['total_alerts']}")

    print("-" * 75)

    print(f"CRITICAL : {summary['critical']}")

    print(f"HIGH     : {summary['high']}")

    print(f"MEDIUM   : {summary['medium']}")

    print(f"LOW      : {summary['low']}")

    print(f"INFO     : {summary['info']}")

    print("-" * 75)

    print("SOURCE-WISE ALERTS")

    for source, count in report["source_summary"].items():

        print(f"{source}: {count}")

    print("-" * 75)

    activity = report["process_activity"]

    print("PROCESS ACTIVITY")

    print(f"Total Events: {activity['total_events']}")

    print(f"Process Started: {activity['process_started']}")

    print(f"Process Terminated: {activity['process_terminated']}")

    print("-" * 75)

    print("LATEST SECURITY FINDINGS")

    for alert in report["alerts"][:10]:

        print(
            f"\n[{alert['severity']}] {alert['rule']}"
        )

        print(f"Source: {alert['source']}")

        print(f"Reason: {alert['reason']}")

    print("\n" + "=" * 75)

    print(f"Central Report Saved: {OUTPUT_FILE}")

    print("=" * 75)


# ==========================================
# MAIN
# ==========================================

def main():

    print("=" * 75)

    print("INITIALIZING CENTRAL ALERT ENGINE")

    print("=" * 75)

    report = generate_central_report()

    display_report(report)


if __name__ == "__main__":

    main()
