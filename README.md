# SOC Detection Lab — Sysmon, Splunk & MITRE ATT&CK Simulation

A hands-on home lab built to practice SOC analyst skills: log collection, detection engineering, and investigation — using an isolated Windows VM, Sysmon, Splunk, and Atomic Red Team to safely simulate real attacker techniques and build working detections against them.

## Overview

Rather than just studying SOC concepts, this project simulates individual MITRE ATT&CK techniques in a fully isolated lab and builds/validates real detections for each one — including the mistakes made along the way, since debugging a broken detection is as much a part of the job as building one.

## Architecture

- **Windows 10 VM** (VirtualBox, Host-Only network + NAT) — the "victim" machine, fully isolated from the real network
- **Sysmon** (SwiftOnSecurity config) — detailed endpoint telemetry: process creation, network connections, registry changes
- **Splunk Universal Forwarder** — ships VM telemetry to the indexer
- **Splunk Enterprise (Free license)** — runs on the host machine, indexes and searches all collected data
- **Atomic Red Team** — open-source library of scoped, safe technique simulations mapped to MITRE ATT&CK

```
Sysmon (VM) → Universal Forwarder (VM) → [Host-Only Network, port 9997] → Splunk Indexer (Host) → Search & Alerts
```

## Techniques Simulated

### 1. T1547.001 — Persistence: Registry Run Keys
**What it does:** Adds a value to a Registry Run key so a program launches automatically at every logon — one of the most common real-world persistence mechanisms.

**Telemetry:** Sysmon `EventCode=13` (Registry value set)

**Detection query:**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Run\\*"
| table _time, Image, TargetObject, Details
```

**Key takeaway:** `reg.exe` writing to a Run key is a classic "living off the land" pattern — a legitimate built-in tool used for a malicious purpose, which is exactly why signature-only detection isn't enough; the registry path and value name matter more than the tool used.

---

### 2. T1059.001 — Execution: PowerShell Encoded Commands
**What it does:** Executes a PowerShell command using Base64 encoding (`-EncodedCommand`) to obscure the actual command from casual inspection.

**Telemetry:** Sysmon `EventCode=1` (Process creation)

**The mistake:** My first detection used a naive substring match (`CommandLine="*enc*"`), which both **missed the real attack** (it used the `-E` short-form parameter, not the full `-EncodedCommand`) and **generated false positives** from unrelated Microsoft Edge update traffic that happened to contain "enc" inside an unrelated Base64 blob.

**Fixed detection query:**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)-e(nc(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?\s"
| table _time, Image, ParentImage, CommandLine, ProcessId
```

**Key takeaway:** Naive text-matching detections are fragile — attackers deliberately exploit parameter abbreviation to evade exactly this kind of rule. A production detection needs to account for every valid variation of a switch, not just the most common form.

---

### 3. T1071.001 — Command & Control: Web Protocols (Malicious User-Agent)
**What it does:** Sends an HTTP request using a User-Agent string associated with known malware/C2 frameworks.

**What actually happened:** Windows Defender's AMSI (Antimalware Scan Interface) blocked the script before it ever executed, because the specific User-Agent string matched a known malicious signature. This surfaced an important distinction: **AMSI is a pre-execution, signature-based defense layer, separate entirely from log-based (Sysmon/SIEM) detection.** To observe the full network telemetry, real-time protection was temporarily disabled inside the isolated, network-restricted lab VM only, and re-enabled immediately after.

**Key takeaway:** Real environments have multiple independent defensive layers. A SOC analyst needs to understand what each layer can and can't see — Sysmon/Splunk shows you what happened on the endpoint and network, but has no visibility into HTTP payload content (like User-Agent strings) without a proxy or packet-level tool.

---

### 4. T1110-style — Credential Access: Password Guessing / Brute Force
**What it does:** Simulates repeated failed login attempts against a single account (Active Directory-specific Atomic Red Team tests didn't fit this standalone, non-domain lab, so this was simulated locally using the Windows `LogonUser` API against a local test account).

**Telemetry:** Windows Security log, `EventCode=4625` (failed logon)

**A Windows quirk:** Each 4625 event logs two account names — the *Subject* (the initiating machine/service account) and the actual *target* account being attacked. Both land in Splunk's parsed `Account_Name` field as a multivalue field, requiring `mvindex(Account_Name, 1)` to correctly isolate the target.

**Detection query (with real-world false-positive consideration):**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625 earliest=-5m
| eval target_account=mvindex(Account_Name, 1)
| stats count as failed_attempts, values(Source_Network_Address) as source_ips, earliest(_time) as first_attempt, latest(_time) as last_attempt by target_account
| where failed_attempts >= 5 AND source_ips!="127.0.0.1"
| eval first_attempt=strftime(first_attempt, "%Y-%m-%d %H:%M:%S"), last_attempt=strftime(last_attempt, "%Y-%m-%d %H:%M:%S")
```

Turned into a real scheduled Splunk alert (cron: `*/5 * * * *`).

**The bug:** The alert didn't fire on the first test — not because the detection logic was wrong, but because the alert was scheduled to run hourly instead of every 5 minutes, so it simply hadn't checked yet against the search window. **A correct query on the wrong schedule is a broken alert.**

**Key takeaway:** Detection engineering isn't just about the query — the schedule, the window, and the false-positive filtering (excluding known-good source IPs) all matter just as much as the search logic itself.

---

### 5. T1082 — Discovery: System Information Discovery
**What it does:** Runs `systeminfo` and a registry query chained together via `cmd.exe`.

**Telemetry:** Sysmon `EventCode=1`

**The real finding:** The chained command queried `HKLM\SYSTEM\CurrentControlSet\Services\Disk\Enum` — a registry key commonly used by malware for **anti-sandbox/VM-detection**, since virtualized environments leave giveaway strings (like "VBOX") in disk driver names there.

**Detection query — built on behavior, not content:**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*systeminfo.exe"
| where like(ParentCommandLine, "%&%")
| table _time, User, ParentImage, ParentCommandLine, CommandLine
```

**Key takeaway:** `systeminfo` alone is completely routine — the signal here is entirely contextual (multiple discovery commands scripted together via `&`), not the command itself. This is a genuinely harder detection category than signature-based techniques, since no single "bad" string exists.

---

### 6. T1021.002 — Lateral Movement: SMB / Windows Admin Shares
**What it does:** Maps an admin share (`\\<target>\C$`) — a common method (used by tools like PsExec, and historically by WannaCry) for moving between systems on a network.

**The debugging arc (single-VM lab, no second host available):**
1. Default test used a placeholder hostname → fixed by targeting `localhost`
2. Technique "succeeded" but generated no useful authentication telemetry → diagnosed as Windows reusing the existing session token rather than performing a fresh network authentication, since no real trust boundary was crossed
3. Forced real authentication using explicit credentials → hit `Access is denied` (Windows error 5)
4. Diagnosed as **UAC Remote Restriction** (`LocalAccountTokenFilterPolicy`) — a real Windows security control that denies full admin tokens to non-built-in local admin accounts over the network
5. Adjusted the policy in the lab (safe on an isolated VM) → captured clean `EventCode=4624`, `Logon_Type=3` authentication events

**Key takeaway:** Admin share access is telemetry-identical whether performed by a legitimate sysadmin or an attacker moving laterally — same event code, same logon type. Real detection here has to be behavioral/baseline-driven (is this account, source host, and timing normal?), since indicator-based detection fundamentally cannot distinguish the two.

## Skills Demonstrated

- End-to-end log pipeline design and troubleshooting (network, service permissions, file/config issues)
- SPL query writing, including multivalue field handling (`mvindex`) and regex-based detection logic
- Correlation searches with thresholds, turned into real scheduled Splunk alerts
- False positive diagnosis and detection tuning
- Understanding of Windows internals: registry structure, event log auditing, UAC token filtering, service accounts
- MITRE ATT&CK mapping across five tactics: Persistence, Execution, Command & Control, Credential Access, Discovery, and Lateral Movement

## What I'd Explore Next

- Defense Evasion techniques (e.g. process injection indicators, AMSI bypass patterns)
- A second VM to properly test lateral movement across a real trust boundary
- Migrating part of this lab to the ELK stack for comparison with Splunk

## Notes on Lab Safety

All techniques were executed using [Atomic Red Team](https://github.com/redcanaryco/invoke-atomicredteam), an open-source project maintained specifically for safe, scoped detection testing. All activity was contained to an isolated VM on a host-only virtual network with no route to any real network. No custom malware, exploits, or unauthorized targets were used at any point in this project.
