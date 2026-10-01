#Security Incident Response Automation Tool

import sys
import json
from pathlib import Path 
from datetime import datetime
import shutil
import subprocess
import psutil
import ipaddress


def main():
    if len(sys.argv) != 3:
        sys.exit("Usage: <program> <command> <filename / incident>")

    command = sys.argv[1]
    if command == "add":
        alert_path = sys.argv[2]
        incident = create_incident(alert_path)
        report(incident)
    elif command == "investigate":
        incident_id = sys.argv[2]
        begin_investigation(incident_id)
    elif command == "audit":
        incident_id = sys.argv[2]
        incident = find_incident(incident_id)
        report_audit(incident)
    else:
        sys.exit("Invalid command. Commands: add | investigate | audit")


def create_incident(alert_path):
    highest = 0
    if not Path(alert_path).exists():
        sys.exit("Alert file doesnt exist")

    try:
        with open(alert_path, "r") as alert_file:
            alert = json.load(alert_file)
    except json.JSONDecodeError:
        sys.exit("Invalid JSON in alert file")

    if not isinstance(alert, dict):
        sys.exit("Invalid alert structure.")

    existing_incidents = []
    if Path("incidents.json").exists():
        with open("incidents.json", "r") as incidents_file:
            existing_incidents = json.load(incidents_file)

        for stored_incident in existing_incidents:
            _, number = stored_incident["incident_id"].split("-")
            if int(number) > highest:
                highest = int(number)

    incident_id = f"INC-{highest + 1:03d}"
    incident_type = alert.get("type")
    incident_severity = alert.get("severity")
    incident_source = alert.get("source")
    incident_timestamp = alert.get("timestamp")
    incident_details = alert.get("details")
    incident_evidence = alert.get("evidence")

    if incident_type not in ("suspicious_network_activity", "malware_detection"):
        sys.exit("Invalid incident type.")
    if incident_severity not in ("low", "medium", "high"):
        sys.exit("Invalid incident severity.")
    try:
        ipaddress.ip_address(incident_source)
    except (ValueError, TypeError):
        sys.exit("Invalid source IP address.")
    try:
        datetime.fromisoformat(incident_timestamp)
    except (ValueError, TypeError):
        sys.exit("Invalid timestamp format.")
    if not incident_details:
        sys.exit("Invalid incident details.")
    if not incident_evidence:
        sys.exit("Invalid incident evidence.")

    incident = {
        "incident_id": incident_id,
        "type": incident_type,
        "severity": incident_severity,
        "source": incident_source,
        "timestamp": incident_timestamp,
        "details": incident_details,
        "evidence": incident_evidence,
        "status": "NEW",
        "audit_trail": []
    }

    event = "INCIDENT_CREATED"
    record_audit(incident, event)

    existing_incidents.append(incident)
    with open("incidents.json", "w") as incidents_file:
        json.dump(existing_incidents, incidents_file, indent=4)

    return incident


def begin_investigation(incident_id):
    found = False
    with open("incidents.json", "r") as incidents_file:
        incidents = json.load(incidents_file)
        for incident in incidents:
            if incident_id == incident["incident_id"]:
                found = True
                if incident["status"] == "NEW":
                    incident["status"] = "INVESTIGATING"
                    event = "INVESTIGATION_BEGAN"
                    record_audit(incident, event)
                    investigation_dispatch(incident)
                else:
                    sys.exit("Invalid status assignment. <NEW → INVESTIGATING → RESOLVED> ")

                break

    if not found:
        sys.exit("Incident not found")
        
    with open("incidents.json", "w") as incidents_file:
        json.dump(incidents, incidents_file, indent=4)


#----------------------Investigation Functionalities----------------------#

def investigation_dispatch(incident):
    if incident["type"] == "suspicious_network_activity":
        investigate_network(incident)
        report(incident)
        resolve_network(incident)
        event = "INCIDENT_RESOLVED"
        record_audit(incident, event)
        report(incident)

    elif incident["type"] == "malware_detection":
        investigate_malware(incident)
        report(incident)
        resolve_malware(incident)
        event = "INCIDENT_RESOLVED"
        record_audit(incident, event)
        report(incident)
        
    else:
        sys.exit("Unsupported incident type")


def investigate_network(incident):
    severity = incident["severity"]
    try:
        time_window = incident["evidence"]["time_window"]
    except (KeyError, TypeError):
        sys.exit("Invalid time_window field in incident")

    incident["investigation"] = {
        "finding": "Alert did not meet any suspicious threshold",
        "assessment": "Not Suspicious",
        "recommended_action": "NO_ACTION"
    }

    if "SSH" in incident["details"]:
        try:
            failed_attempts = incident["evidence"]["failed_authentications"]
        except (KeyError, TypeError):
            sys.exit("Invalid failed_authentications field in incident")

        if failed_attempts >= 15 and time_window <= 120 and severity == "high":
            incident["investigation"] = {
                "finding": "High-volume SSH connection activity detected",
                "assessment": "Suspicious",
                "recommended_action": "BLOCK_IP"
            }

    elif "port scanning" in incident["details"]:
        try:
            port_count = incident["evidence"]["destination_ports"]
        except (KeyError, TypeError):
            sys.exit("Invalid port_count field in incident")

        if port_count >= 20 and time_window <= 60 and severity == "medium":
            incident["investigation"] = {
                "finding": "Probable Port-scanning/reconnaissance behavior",
                "assessment": "Suspicious",
                "recommended_action": "MONITOR_IP"
            }


def investigate_malware(incident):
    severity = incident["severity"]

    incident["investigation"] = {
        "finding": "Alert did not meet any suspicious threshold",
        "assessment": "Not Suspicious",
        "recommended_action": "NO_ACTION"
    }

    if "file" in incident["details"]:
        try:
            flags = incident["evidence"]["antivirus_flags"]
        except (KeyError, TypeError):
            sys.exit("Invalid flags field in incident")

        if flags >= 3 and severity == "high":
            incident["investigation"] = {
                "finding": "Probable malicious file on source host",
                "assessment": "Suspicious",
                "recommended_action": "QUARANTINE_FILE"
            }

    elif "process" in incident["details"]:
        try:
            process_count = incident["evidence"]["child_process_count"]
            connections = incident["evidence"]["outbound_connections"]
        except (KeyError, TypeError):
            sys.exit("Invalid evidence field in incident")
        if process_count >= 5 and connections >= 10 and severity == "high":
            incident["investigation"] = {
                "finding": "Malicious process activity detected",
                "assessment": "Suspicious",
                "recommended_action": "TERMINATE_PROCESS"
            }


#----------------------Network Resolution Dispatcher----------------------#

def resolve_network(incident):
    assessment = incident["investigation"]["assessment"]
    recommended_action = incident["investigation"]["recommended_action"]

    if assessment == "Not Suspicious":
        incident["status"] = "RESOLVED"
        incident["resolution"] = "No Action Needed"

    elif assessment == "Suspicious" and recommended_action == "BLOCK_IP":
        result = block_ip(incident)
        if result:
            incident["status"] = "RESOLVED"
            suspicious_ip = incident["source"]
            incident["resolution"] = f"IP - {suspicious_ip} | Status - BLOCKED"

    elif assessment == "Suspicious" and recommended_action == "MONITOR_IP":
        result = monitor_ip(incident)
        if result:
            incident["status"] = "RESOLVED"
            suspicious_ip = incident["source"]
            incident["resolution"] = f"IP - {suspicious_ip} | Status - Placed in monitor_ips.json for tracking"


#-----------------------Specific Network Resolutions-----------------------#

def block_ip(incident):
    if not Path("blocked_ips.json").exists():
        with open("blocked_ips.json", "w") as blocked_ip_list:
            json.dump([], blocked_ip_list)

    with open("blocked_ips.json", "r") as blocked_ip_list:
        blocked_list = json.load(blocked_ip_list)
    suspicious_ip = incident["source"]

    if suspicious_ip not in blocked_list:
        with open("blocked_ips.json", "w") as blocked_ip_list:
            blocked_list.append(suspicious_ip)

            event = "RESPONSE_EXECUTED"
            record_audit(incident, event)

            json.dump(blocked_list, blocked_ip_list, indent=4)
    return True


def monitor_ip(incident):
    if not Path("monitor_ips.json").exists():
        with open("monitor_ips.json", "w") as monitored_ip_list:
            json.dump([], monitored_ip_list)

    with open("monitor_ips.json", "r") as monitored_ip_list:
        monitor_list = json.load(monitored_ip_list)
    suspicious_ip = incident["source"]
    
    if suspicious_ip not in monitor_list:
        with open("monitor_ips.json", "w") as monitored_ip_list:
            monitor_list.append(suspicious_ip)
    
            event = "RESPONSE_EXECUTED"
            record_audit(incident, event)
    
            json.dump(monitor_list, monitored_ip_list, indent=4)
    return True


#----------------------Malware Resolution Dispatcher----------------------#

def resolve_malware(incident):
    assessment = incident["investigation"]["assessment"]
    recommended_action = incident["investigation"]["recommended_action"]

    if assessment == "Not Suspicious":
        incident["status"] = "RESOLVED"
        incident["resolution"] = "No Action Needed"

    elif assessment == "Suspicious" and recommended_action == "QUARANTINE_FILE":
        result = quarantine_file(incident)
        if result:
            incident["status"] = "RESOLVED"
            suspicious_file = incident["evidence"]["file_path"]
            incident["resolution"] = f"Suspicious File: {suspicious_file} | Status - QUARANTINED"

    elif assessment == "Suspicious" and recommended_action == "TERMINATE_PROCESS":
        start_dummy_process()
        result = terminate_process(incident)
        if result:
            incident["status"] = "RESOLVED"
            process_id = result
            process_name = incident["evidence"]["process_name"]
            incident["resolution"] = f"Name - {process_name} | PID - {process_id} | Status - TERMINATED"
        

#-----------------------Specific Malware Resolutions-----------------------#

def quarantine_file(incident):
    try:
        file_path = incident["evidence"]["file_path"]
    except (KeyError, TypeError):
        sys.exit("Invalid file_path field in incident")

    filename = Path(file_path).name

    event = "RESPONSE_EXECUTED"
    record_audit(incident, event)

    if Path(file_path).exists():
        Path("quarantine/").mkdir(exist_ok=True)
        shutil.move(file_path, f"quarantine/{filename}")
        return True


#Starts a dummy process for the terminate function to test properly
def start_dummy_process():
    process = subprocess.Popen(["python3", "dummy_process.py"])
    return process

def terminate_process(incident):
    process_name = incident["evidence"]["process_name"]
    
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        if proc.info["cmdline"] == ["python3", process_name]:
            process_id = proc.info["pid"]

            event = "RESPONSE_EXECUTED"
            record_audit(incident, event)

            proc.terminate()
            return process_id

    return None


#--------------------------Reporting and Auditing--------------------------#

def record_audit(incident, event):
    audit_trail = incident["audit_trail"]
    timestamp = datetime.now().isoformat()

    if event == "INCIDENT_CREATED":
        audit_details = incident["details"]
    elif event == "INVESTIGATION_BEGAN":
        audit_details = "Investigation started"
    elif event == "RESPONSE_EXECUTED":
        audit_details = incident["investigation"]["recommended_action"]
    elif event == "INCIDENT_RESOLVED":
        audit_details = incident["resolution"]
    else:
        sys.exit("Unsupported audit event")
    
    audit_entry = {
        "event": event,
        "timestamp": timestamp,
        "description": audit_details
    }
    audit_trail.append(audit_entry)


def report(incident):
    incident_id = incident["incident_id"]
    incident_type = incident["type"]
    severity = incident["severity"]
    source = incident["source"]
    timestamp = incident["timestamp"]
    details = incident["details"]
    status = incident["status"]
    

    if status == "NEW":
        print(f"Incident Created\n---------------------------------")
        print(f" ID: {incident_id}\n Type: {incident_type}\n Severity: {severity}\n Source: {source}\n Timestamp: {timestamp}\n Details: {details}\n Evidence: {json.dumps(incident['evidence'])}\n Status: {status}\n")

    elif status == "INVESTIGATING":
        investigation = incident["investigation"]
        finding = investigation["finding"]
        assessment = investigation["assessment"]
        recommended_action = investigation["recommended_action"]
        print(f"Incident Updated\n---------------------------------")
        print(f" ID: {incident_id}\n Changed to: {status}\n Finding: {finding}\n Assessment: {assessment}\n Recommended Action: {recommended_action}\n")

    elif status == "RESOLVED":
        resolution = incident["resolution"]
        print(f"Incident Resolved\n---------------------------------")
        print(f" ID: {incident_id}\n Changed to: {status}\n Resolution: {resolution}\n")


def find_incident(incident_id):
    with open("incidents.json", "r") as incidents_file:
        incidents = json.load(incidents_file)
        for incident in incidents:
            if incident_id == incident["incident_id"]:
                return incident

    sys.exit("Incident not found")


def report_audit(incident):
    audit_trail = incident["audit_trail"]
    incident_id = incident["incident_id"]

    print(f"Audit Trail\n---------------------------------")
    print(f" Incident ID: {incident_id}\n")

    for audit_entry in audit_trail:
        event = audit_entry["event"]
        timestamp = audit_entry["timestamp"]
        description = audit_entry["description"]

        print(f" Event: {event}\n Timestamp: {timestamp}\n Description: {description}\n")


if __name__ == "__main__":
    main()
