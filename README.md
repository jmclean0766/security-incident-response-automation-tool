# Security Incident Response Automation Tool (SIRAT)

A Python-based incident response tool that automates the intake, investigation, response, resolution, reporting, and auditing of security incidents.

## Overview

SIRAT simulates a security incident response workflow by accepting structured security alerts, creating tracked incidents, investigating incidents based on predefined evidence and thresholds, executing response actions, and maintaining an audit trail of incident activity.

The project is designed to demonstrate practical security operations concepts such as incident lifecycle management, investigation logic, automated response, evidence-based decision making, and security auditing.

## Features

- Accepts security alerts in JSON format
- Creates unique incident IDs
- Supports suspicious network activity and malware detection incidents
- Validates incident type, severity, source IP, timestamp, details, and evidence
- Tracks incident status from `NEW` → `INVESTIGATING` → `RESOLVED`
- Performs evidence-based investigation using predefined detection thresholds
- Recommends response actions based on investigation findings
- Executes simulated response actions
- Maintains an incident audit trail
- Generates incident status and investigation reports
- Supports incident audit reporting
- Records response actions and resolution details

## Technologies

- Python 3
- JSON
- `pathlib`
- `datetime`
- `ipaddress`
- `psutil`
- `subprocess`

## Incident Workflow

```text
Security Alert
      │
      ▼
Create Incident
      │
      ▼
NEW
      │
      ▼
Begin Investigation
      │
      ▼
INVESTIGATING
      │
      ▼
Investigation & Assessment
      │
      ▼
Recommended Response
      │
      ▼
Response Execution
      │
      ▼
RESOLVED
      │
      ▼
Audit Trail
```

## Supported Incident Types

### Suspicious Network Activity

SIRAT evaluates network activity using incident severity and evidence such as:

- Failed authentication attempts
- Time windows
- Destination port counts
- Incident details

Possible investigation outcomes include:

- No action required
- Block the source IP
- Place the source IP under monitoring

### Malware Detection

SIRAT evaluates malware-related alerts using evidence such as:

- Antivirus detection count
- Child process count
- Outbound network connections
- Incident severity

Possible response actions include:

- No action required
- Quarantine a suspicious file
- Terminate a suspicious process

## Response Actions

The response functions in SIRAT are **simulation and integration placeholders** representing actions that an incident response system could perform against real infrastructure.

The project demonstrates the decision-making and automation workflow without directly modifying external security infrastructure.

For example:

- `block_ip()` could be extended to interact with a firewall, network security appliance, cloud security group, or other access-control mechanism to block a malicious IP.
- `monitor_ip()` could be connected to a monitoring platform, SIEM, firewall, or threat-intelligence system to track suspicious addresses.
- `quarantine_file()` could be integrated with an endpoint detection and response (EDR) platform or endpoint security solution to isolate a malicious file.
- `terminate_process()` could be extended to interact with an endpoint security platform or host-management system to terminate a malicious process.

This separation allows the project to demonstrate the **incident investigation → decision → automated response** workflow while keeping the response functions modular enough to be connected to real-world security infrastructure in a production implementation.

### IP Blocking

Suspicious source IP addresses identified for blocking are added to `blocked_ips.json` by the current implementation.

In a production environment, this function could instead interface with a firewall or other network security control to enforce the block.

### IP Monitoring

Source IP addresses requiring continued observation are added to `monitor_ips.json`.

In a production environment, this could be replaced with an integration with a SIEM, firewall, network monitoring platform, or threat-intelligence system.

### File Quarantine

Suspicious files are moved into the `quarantine/` directory.

In a production environment, this functionality could be integrated with an endpoint security or EDR platform capable of isolating files from a host.

### Process Termination

For testing purposes, SIRAT can launch a dummy process and identify and terminate the corresponding process using `psutil`.

In a production environment, this functionality could be integrated with an endpoint security or host-management platform.

## Incident Auditing

Each incident maintains an audit trail containing timestamped events such as:

- `INCIDENT_CREATED`
- `INVESTIGATION_BEGAN`
- `RESPONSE_EXECUTED`
- `INCIDENT_RESOLVED`

This provides a record of the actions taken throughout the incident lifecycle.

## Usage

### Create an Incident

```bash
python3 security_incident_response_tool.py add <alert_file.json>
```

Creates an incident from a JSON alert and assigns a unique incident ID.

### Investigate an Incident

```bash
python3 security_incident_response_tool.py investigate <incident_id>
```

Begins the investigation, evaluates the available evidence, performs the appropriate response action, and resolves the incident.

### Audit an Incident

```bash
python3 security_incident_response_tool.py audit <incident_id>
```

Displays the incident's audit trail and recorded response activity.

## Example

```bash
python3 security_incident_response_tool.py add alerts/ssh_activity.json
```

After an incident is created, the returned incident ID can be used to begin the investigation:

```bash
python3 security_incident_response_tool.py investigate INC-001
```

The incident can then be audited:

```bash
python3 security_incident_response_tool.py audit INC-001
```

## Data Storage

SIRAT currently uses JSON files for persistent data storage.

Examples include:

```text
incidents.json
blocked_ips.json
monitor_ips.json
```

The project also uses a `quarantine/` directory for files isolated during malware-response testing.

## Project Structure

```text
security-incident-response-automation-tool/
├── security_incident_response_tool.py
├── incidents.json
├── blocked_ips.json
├── monitor_ips.json
├── dummy_process.py
├── quarantine/
└── alerts/
```

## Security Operations Concepts Demonstrated

- Incident lifecycle management
- Security alert triage
- Evidence-based investigation
- Detection thresholds
- Automated incident response
- IP containment
- File quarantine
- Process termination
- Incident auditing
- Security event reporting
- Response automation
- Security infrastructure integration concepts

## Project Status

Completed.

This project was developed as a practical Python cybersecurity project to simulate an automated security incident response workflow.

## Limitations

This project is a learning and portfolio implementation rather than a production incident response platform.

Response actions currently operate locally or against project-specific JSON files. The response functions are intentionally structured as placeholders for future integrations with real-world security infrastructure such as firewalls, SIEM platforms, endpoint security/EDR systems, or cloud security controls.

Detection thresholds and investigation logic are predefined within the application and are intended to demonstrate the decision-making process rather than replace enterprise detection and response systems.
