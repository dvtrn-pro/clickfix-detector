# ClickFix / Fake CAPTCHA Attack Detector — CSV Version
# Detects Word or Excel spawning PowerShell via Sysmon logs
# MITRE ATT&CK: T1059.001, T1204.002, T1566.001
# Usage: python clickfix_hunter_csv.py sysmon_logs.csv

import pandas as pd
from datetime import datetime

# Word and Excel should never launch PowerShell
SUSPICIOUS_PAIRS = {
    "winword.exe": ["powershell.exe"],
    "excel.exe":   ["powershell.exe"],
}

# PowerShell flags that indicate a hidden encoded command
ENCODING_FLAGS = ["-enc", "-encodedcommand", "-e "]


def load_logs(filepath):
    # Load CSV and normalize column headers to lowercase
    df = pd.read_csv(filepath)
    df.columns = [c.lower().strip() for c in df.columns]
    return df


def extract_process_name(path):
    # Pull just the .exe name from a full Windows path
    if pd.isna(path):
        return ""
    return path.strip().split("\\")[-1].lower()


def is_encoded(commandline):
    # Check if the PowerShell command is Base64 encoded
    if pd.isna(commandline):
        return False
    return any(flag in commandline.lower() for flag in ENCODING_FLAGS)


def hunt_clickfix(df):
    findings = []

    for _, row in df.iterrows():
        parent = extract_process_name(row.get("parentimage", ""))
        child  = extract_process_name(row.get("image", ""))

        # Flag it if Word or Excel launched PowerShell
        if parent in SUSPICIOUS_PAIRS:
            if child in SUSPICIOUS_PAIRS[parent]:
                commandline = row.get("commandline", "N/A")
                encoded     = is_encoded(commandline)

                findings.append({
                    "time":        row.get("utctime", "unknown"),
                    "parent":      parent,
                    "child":       child,
                    "commandline": commandline,
                    "encoded":     encoded,
                    "user":        row.get("user", "N/A"),
                    "hostname":    row.get("computer", "N/A"),
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
    import sys

    filepath = sys.argv[1] if len(sys.argv) > 1 else "sysmon_logs.csv"
    print(f"📂 Loading logs from: {filepath}")

    df       = load_logs(filepath)
    findings = hunt_clickfix(df)
    print_report(findings)
