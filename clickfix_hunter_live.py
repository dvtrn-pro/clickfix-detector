# ClickFix / Fake CAPTCHA Attack Detector — Live Version
# Reads directly from Windows Event Log — no CSV needed
# Requires: pip install pywin32 | Run as Administrator
# MITRE ATT&CK: T1059.001, T1204.002, T1566.001
# Usage: python clickfix_hunter_live.py

import win32evtlog
import xml.etree.ElementTree as ET
from datetime import datetime

# Word and Excel should never launch PowerShell
SUSPICIOUS_PAIRS = {
    "winword.exe": ["powershell.exe"],
    "excel.exe":   ["powershell.exe"],
}

# PowerShell flags that indicate a hidden encoded command
ENCODING_FLAGS = ["-enc", "-encodedcommand", "-e "]


def extract_process_name(path):
    # Pull just the .exe name from a full Windows path
    if not path:
        return ""
    return path.strip().split("\\")[-1].lower()


def is_encoded(commandline):
    # Check if the PowerShell command is Base64 encoded
    if not commandline:
        return False
    return any(flag in commandline.lower() for flag in ENCODING_FLAGS)


def read_sysmon_logs():
    # Read Sysmon Event ID 1 (Process Creation) directly from Windows Event Log
    events = []

    query_handle = win32evtlog.EvtQuery(
        "Microsoft-Windows-Sysmon/Operational",
        win32evtlog.EvtQueryChannelPath,
        "Event/System[EventID=1]",
        None
    )

    while True:
        batch = win32evtlog.EvtNext(query_handle, 100)
        if not batch:
            break

        for event in batch:
            xml_content = win32evtlog.EvtRender(event, win32evtlog.EvtRenderEventXml)
            event_data  = parse_sysmon_xml(xml_content)
            if event_data:
                events.append(event_data)

    return events


def parse_sysmon_xml(xml_content):
    # Parse the XML event and return just the fields we need
    try:
        root = ET.fromstring(xml_content)
        ns   = {"ns": "http://schemas.microsoft.com/win/2004/08/events/event"}

        event_data = {}
        for data in root.findall(".//ns:EventData/ns:Data", ns):
            event_data[data.get("Name", "")] = data.text or ""

        return {
            "time":        event_data.get("UtcTime", "unknown"),
            "image":       event_data.get("Image", ""),
            "parentimage": event_data.get("ParentImage", ""),
            "commandline": event_data.get("CommandLine", ""),
            "user":        event_data.get("User", ""),
            "computer":    event_data.get("Computer", ""),
        }
    except ET.ParseError:
        return None


def hunt_clickfix(events):
    findings = []

    for event in events:
        parent = extract_process_name(event["parentimage"])
        child  = extract_process_name(event["image"])

        # Flag it if Word or Excel launched PowerShell
        if parent in SUSPICIOUS_PAIRS:
            if child in SUSPICIOUS_PAIRS[parent]:
                commandline = event["commandline"]
                encoded     = is_encoded(commandline)

                findings.append({
                    "time":        event["time"],
                    "parent":      parent,
                    "child":       child,
                    "commandline": commandline,
                    "encoded":     encoded,
                    "user":        event["user"],
                    "hostname":    event["computer"],
                    "mitre":       "T1059.001 / T1204.002 / T1566.001",
                    "confidence":  "CRITICAL" if encoded else "HIGH"
                })

    return findings


def print_report(findings):
    if not findings:
        print("✅ No ClickFix / Fake CAPTCHA activity detected.")
        return

    print(f"\n🚨 CLICKFIX ATTACK REPORT — {datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}")
    print(f"{'='*60}")
    print(f"Total findings: {len(findings)}")

    encoded_count = sum(1 for f in findings if f["encoded"])
    print(f"Encoded PowerShell commands: {encoded_count} (highest severity)\n")

    for i, f in enumerate(findings, 1):
        print(f"[{i}] Confidence: {f['confidence']} | MITRE: {f['mitre']}")
        print(f"    Time:     {f['time']}")
        print(f"    Host:     {f['hostname']}  |  User: {f['user']}")
        print(f"    Chain:    {f['parent']} → {f['child']}")
        print(f"    Command:  {f['commandline']}")
        if f["encoded"]:
            print(f"    ⚠️  Base64 encoded command — attacker is hiding payload")
        print()


if __name__ == "__main__":
    print("📂 Reading live Sysmon logs from Windows Event Log...")
    print("⚠️  Note: Must be run as Administrator\n")

    events   = read_sysmon_logs()
    findings = hunt_clickfix(events)
    print_report(findings)
