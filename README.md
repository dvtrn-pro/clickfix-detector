# ClickFix / Fake CAPTCHA Attack Detector 🔍

A Python script that detects when Microsoft Word or Excel launches 
PowerShell — which is a sign of a malicious macro attack.

---

## How This Project Started

At a previous job our email gateway flagged a suspicious email but 
didn't block it — it sent an alert to our PhishAnalyzer queue for 
the SOC team to review.

We pulled the attachment and ran it through a sandbox which showed 
a Word/Excel document spawning encoded PowerShell. This confirmed it was 
a ClickFix attack — where a malicious document shows a fake CAPTCHA 
or "I'm not a robot" prompt that silently runs a macro when clicked.

I was curious to understand how you would detect that same behavior 
at the endpoint level using raw process logs. So I built this script 
to learn the detection logic myself and validate what the sandbox 
was already showing us.

---

## What I Learned From Building This

- How Sysmon captures process creation events on Windows
- Why parent-child process relationships are a red flag
  (Word should never open a command shell during normal use)
- What Base64 encoded PowerShell commands look like and why
  attackers use them to hide what they're doing
- How to map what I was seeing to MITRE ATT&CK techniques
- How endpoint detection complements email gateway and sandbox tools

---

## The SOC Workflow That Inspired This
```
Phishing email with fake CAPTCHA attachment sent to user
        ↓
Email gateway flags it as suspicious but delivers anyway
        ↓
Alert sent to PhishAnalyzer queue for SOC review
        ↓
SOC pulls attachment and runs it through sandbox
        ↓
Sandbox confirms Word/Excel spawning encoded PowerShell
        ↓
This script validates the same activity via Sysmon logs
```

---

## What The Script Does

1. Reads Sysmon process creation logs (Event ID 1)
2. Looks for Word or Excel launching PowerShell
3. Checks if the PowerShell command is encoded/hidden
4. Outputs a report showing who, what, where and when

---

## Why Word or Excel Launching PowerShell Is Suspicious

Normal everyday use of Word or Excel never requires opening 
a command shell. If this happens it almost always means:

- A malicious macro was hidden inside the document
- The user was tricked into enabling it via a fake CAPTCHA prompt
- The macro is now trying to run commands silently in the background

This technique is known as a **ClickFix attack** and is commonly 
delivered through phishing emails.

**MITRE ATT&CK Mapping:**
| Technique ID | Name | Why It Applies |
|---|---|---|
| T1059.001 | PowerShell | Shell spawned by Office app |
| T1204.002 | Malicious File | User opened infected document |
| T1566.001 | Phishing Attachment | Delivered via email |

---

## Two Versions

I built two versions as I was learning:

**Version 1 — CSV Based**
Reads exported Sysmon logs as a CSV file.
I started with this because it was simpler to test with
and I could create my own sample data to validate it worked.

**Version 2 — Live Log Reader**
Reads directly from the Windows Event Log in real time.
No CSV export needed — just run it on a Windows machine
with Sysmon installed. Requires Administrator privileges.

---

## Requirements

**Version 1 (CSV):**
```bash
pip install pandas
```

**Version 2 (Live):**
```bash
pip install pywin32
```

---

## How To Run It

**Version 1 — CSV:**
```bash
python clickfix_hunter_csv.py sysmon_logs.csv
```

**Version 2 — Live (run as Administrator):**
```bash
python clickfix_hunter_live.py
```

---

## Testing Version 1

I created a sample CSV file to test the script since I didn't 
have real attack logs sitting around. The sample has two 
suspicious rows and one normal row to make sure the script 
only flags what it should.

Create a file called `sysmon_logs.csv` and paste this in:
```
utctime,parentimage,image,commandline,user,computer
2026-03-22 23:47:03,C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,powershell.exe -enc JABjAGwAaQBlAG4AdA==,jsmith,WORKSTATION-04
2026-03-22 23:51:44,C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE,C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe,powershell.exe -nop -w hidden,mlopez,WORKSTATION-07
2026-03-22 23:55:00,C:\Windows\System32\notepad.exe,C:\Windows\System32\calc.exe,calc.exe,bjohnson,WORKSTATION-02
```

The third row is normal activity and should NOT be flagged.

---

## Example Output
```
📂 Loading logs from: sysmon_logs.csv

🚨 CLICKFIX ATTACK REPORT — 2026-03-23 04:12 UTC
============================================================
Total findings: 2
Encoded PowerShell commands: 1 (highest severity)

[1] Confidence: CRITICAL | MITRE: T1059.001 / T1204.002 / T1566.001
    Time:     2026-03-22 23:47:03
    Host:     WORKSTATION-04  |  User: jsmith
    Chain:    winword.exe → powershell.exe
    Command:  powershell.exe -enc JABjAGwAaQBlAG4AdA==
    ⚠️  Base64 encoded command — attacker is hiding payload

[2] Confidence: HIGH | MITRE: T1059.001 / T1204.002 / T1566.001
    Time:     2026-03-22 23:51:44
    Host:     WORKSTATION-07  |  User: mlopez
    Chain:    excel.exe → powershell.exe
    Command:  powershell.exe -nop -w hidden
```

---

## Resources That Helped Me

- [MITRE ATT&CK T1059.001 - PowerShell](https://attack.mitre.org/techniques/T1059/001/)
- [MITRE ATT&CK T1204.002 - Malicious File](https://attack.mitre.org/techniques/T1204/002/)
- [MITRE ATT&CK T1566.001 - Phishing Attachment](https://attack.mitre.org/techniques/T1566/001/)
- [Sysmon Event ID Reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [EVTX Attack Samples](https://github.com/sbousseaden/EVTX-ATTACK-SAMPLES)
- [ClickFix Attack Explanation - Any.run](https://any.run/cybersecurity-blog/clickfix-attack/)
