# SOC Lab — Proof of Concept / Reproduction Steps

Exact commands to reproduce each technique and its detection. Run all commands in an isolated VM only.

---

## 1. T1547.001 — Registry Run Key Persistence

```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1547.001 -TestNumbers 1
```

**Verify in Splunk:**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=13 TargetObject="*\\Run\\*"
| table _time, Image, TargetObject, Details
```

**Cleanup:**
```powershell
Invoke-AtomicTest T1547.001 -TestNumbers 1 -Cleanup
```

---

## 2. T1059.001 — PowerShell Encoded Command

```powershell
Invoke-AtomicTest T1059.001 -TestNumbers 15 -GetPrereqs
Invoke-AtomicTest T1059.001 -TestNumbers 15
```

**Detection (final, regex-based):**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*powershell.exe"
| regex CommandLine="(?i)-e(nc(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?\s"
| table _time, Image, ParentImage, CommandLine, ProcessId
```

---

## 3. T1071.001 — Malicious User-Agent (C2 over HTTP)

```powershell
Set-MpPreference -DisableRealtimeMonitoring $true
Invoke-AtomicTest T1071.001 -TestNumbers 1
Set-MpPreference -DisableRealtimeMonitoring $false
```

**Verify in Splunk:**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" (EventCode=3 OR EventCode=1) earliest=-10m
| table _time, EventCode, Image, ParentImage, CommandLine, DestinationIp, DestinationPort
```
> Real-time protection is disabled only inside the isolated lab VM, for the duration of the test, and re-enabled immediately.

---

## 4. T1110-style — Password Guessing / Brute Force

```powershell
$user = "vboxuser"
$passwords = @("Summer2024", "Password1", "Welcome123", "Qwerty123", "Admin@123", "LetMeIn1")

Add-Type @"
using System;
using System.Runtime.InteropServices;
public class Win32 {
    [DllImport("advapi32.dll", SetLastError = true)]
    public static extern bool LogonUser(string lpszUsername, string lpszDomain, string lpszPassword, int dwLogonType, int dwLogonProvider, out IntPtr phToken);
}
"@

foreach ($pass in $passwords) {
    $token = [IntPtr]::Zero
    [Win32]::LogonUser($user, ".", $pass, 3, 0, [ref]$token) | Out-Null
    Start-Sleep -Milliseconds 500
}
```

**Detection / alert query:**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4625 earliest=-5m
| eval target_account=mvindex(Account_Name, 1)
| stats count as failed_attempts, values(Source_Network_Address) as source_ips, earliest(_time) as first_attempt, latest(_time) as last_attempt by target_account
| where failed_attempts >= 5 AND source_ips!="127.0.0.1"
| eval first_attempt=strftime(first_attempt, "%Y-%m-%d %H:%M:%S"), last_attempt=strftime(last_attempt, "%Y-%m-%d %H:%M:%S")
```
Saved as a Splunk alert, cron schedule `*/5 * * * *`.

---

## 5. T1082 — System Information Discovery

```powershell
Invoke-AtomicTest T1082 -TestNumbers 1 -CheckPrereqs
Invoke-AtomicTest T1082 -TestNumbers 1
```

**Detection (behavior-based):**
```spl
index=main sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*systeminfo.exe"
| where like(ParentCommandLine, "%&%")
| table _time, User, ParentImage, ParentCommandLine, CommandLine
```

---

## 6. T1021.002 — SMB Admin Share (Lateral Movement)

```powershell
Invoke-AtomicTest T1021.002 -TestNumbers 2 -CheckPrereqs
Invoke-AtomicTest T1021.002 -TestNumbers 2 -InputArgs @{computer_name="localhost"}

# To force real authentication instead of session-token reuse:
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f
net use \\localhost\c$ /user:vboxuser <password>
```

**Verify authentication event:**
```spl
index=main sourcetype="WinEventLog:Security" EventCode=4624 earliest=-10m
| eval target_account=mvindex(Account_Name, 1)
| table _time, target_account, Logon_Type, Source_Network_Address
```
Expect `Logon_Type=3`.

---

## Environment Reference

- VM: Windows 10, VirtualBox, Host-Only network (isolated) + NAT (downloads only)
- Sysmon: SwiftOnSecurity config
- Splunk: Free license, Universal Forwarder on VM → Indexer on host, port 9997
- Simulation: Atomic Red Team (redcanaryco/invoke-atomicredteam)
