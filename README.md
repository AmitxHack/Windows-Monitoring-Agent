# Windows Monitoring Agent

**A Python-based Windows Host Security Monitoring and Threat Detection Tool**

Windows Monitoring Agent is a host-based security monitoring project designed to monitor Windows processes and services, identify suspicious activity, detect unauthorized processes, and generate centralized security reports.

The project provides multiple monitoring modules integrated through a central controller.

## Key Features

- **System Information Collection** – Collects basic system information.
- **Process Monitoring** – Monitors running processes and resource utilization.
- **Process Tree Analysis** – Examines parent-child process relationships.
- **Unauthorized Process Detection** – Identifies processes not present in the configured allowlist.
- **Windows Service Auditing** – Audits installed Windows services and their configurations.
- **Service Change Detection** – Detects changes in service configurations against a saved baseline.
- **Service Security Analysis** – Identifies potentially insecure service configurations.
- **Central Alert Engine** – Consolidates findings from monitoring modules.
- **PDF Report Generation** – Generates a structured Windows security assessment report.
- **JSON Logging** – Stores monitoring events and security findings in structured formats.

## Project Architecture

```text
Windows-Monitoring-Agent/
│
├── agent/
│   ├── central_alert_engine.py
│   ├── master_controller.py
│   ├── pdf_report_generator.py
│   ├── process_monitor.py
│   ├── process_test.py
│   ├── process_tracker.py
│   ├── process_tree.py
│   ├── resource_monitor.py
│   ├── service_audit.py
│   ├── service_change_monitor.py
│   ├── service_security_analyzer.py
│   ├── system_info.py
│   └── unauthorized_process_detector.py
│
├── config/
│   ├── process_allowlist.json
│   └── service_baseline.json
│
├── dashboard/
├── detection/
├── logs/
├── reports/
│
├── requirements.txt
└── .gitignore
```

## Technology Stack

| Technology | Purpose |
|---|---|
| Python 3.13 | Core development |
| psutil | Process and system monitoring |
| ReportLab | PDF report generation |
| JSON | Configuration and reporting |
| Windows 11 | Development and testing environment |
| Git & GitHub | Version control |

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/AmitxHack/Windows-Monitoring-Agent.git
```

### 2. Navigate to the project

```bash
cd Windows-Monitoring-Agent
```

### 3. Create a virtual environment

```powershell
python -m venv venv
```

### 4. Activate the virtual environment

```powershell
.\venv\Scripts\Activate.ps1
```

### 5. Install dependencies

```powershell
pip install -r requirements.txt
```

## Usage

Run the master controller:

```powershell
python agent/master_controller.py
```

The controller initializes the monitoring modules and provides the following options:

1. Full Security Scan
2. Process Security Scan
3. Windows Service Security Scan
4. Generate Central JSON + PDF Reports
5. Exit

Follow the on-screen instructions to execute the desired monitoring operation.

## Security Reports

The project generates structured security reports, including:

- `central_alert_report.json`
- `service_audit.json`
- `service_security_report.json`
- `unauthorized_process_report.json`
- `security_assessment_report.pdf`

These reports contain monitoring results and security findings.

## Detection Capabilities

The monitoring engine checks for conditions such as:

- Processes executing from temporary or user-writable locations.
- Processes missing from the configured allowlist.
- Unusual parent-child process relationships.
- Potentially suspicious Windows service configurations.
- Changes in Windows service configurations.
- High CPU and memory utilization.

**Note:** A detection finding is an investigation indicator, not proof of malicious activity. Unknown processes and unusual locations can also be legitimate.

## Configuration

The `config/` directory contains:

- `process_allowlist.json` – Configures recognized processes.
- `service_baseline.json` – Stores the reference service configuration.

Users can review and update these configurations according to their Windows environment.

## Project Objectives

This project was developed to:

- Understand Windows process and service monitoring.
- Explore host-based security monitoring.
- Learn suspicious process identification.
- Understand service security auditing.
- Implement centralized alert processing.
- Generate structured security assessment reports.

## Future Improvements

Potential future enhancements include:

- Interactive web-based security dashboard.
- Real-time alert notifications.
- Windows Event Log integration.
- MITRE ATT&CK mapping.
- Advanced process behavior analysis.
- Improved detection rules and risk scoring.
- Automated scheduled monitoring.

## Limitations

- Detection depends on configured rules and allowlists.
- Unknown processes may generate false positives.
- Some process and service information may require elevated permissions.
- This project is not a replacement for a commercial EDR or antivirus solution.

## Disclaimer

This project is developed for educational purposes, cybersecurity learning, and authorized Windows system monitoring.

Do not use this software to monitor systems without appropriate authorization.

## Author

**Amit Yadav**

- GitHub: https://github.com/AmitxHack
- LinkedIn: https://www.linkedin.com/in/amit-yadav-553554333/
- TryHackMe: https://tryhackme.com/p/ay0073819

---

**Project:** Windows Monitoring Agent  
**Version:** 1.0  
**Status:** Initial development completed
