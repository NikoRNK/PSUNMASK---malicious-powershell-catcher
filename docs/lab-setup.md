# Lab setup: generate real telemetry safely

Use an isolated Windows 10/11 VM (host-only network, snapshot before testing). Never test on a production or personal machine.

## 1. Sysmon
```powershell
# Download Sysmon from Sysinternals and a well-known config (e.g. SwiftOnSecurity or olafhartong/sysmon-modular)
.\Sysmon64.exe -accepteula -i sysmonconfig.xml
```
Check that Event ID 1 appears in `Microsoft-Windows-Sysmon/Operational`.

## 2. PowerShell Script Block Logging
GPO: *Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell > Turn on PowerShell Script Block Logging*. Or locally:
```powershell
New-Item "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" -Force
Set-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" EnableScriptBlockLogging 1
```
Events land in `Microsoft-Windows-PowerShell/Operational` as Event ID 4104.

## 3. Command line auditing (4688)
*Audit Process Creation* (success) plus *Include command line in process creation events*.

## 4. Generate harmless test activity
A benign encoded command is enough to exercise the whole pipeline:
```powershell
$cmd = 'Get-Service | Select-Object -First 3'
$enc = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($cmd))
powershell.exe -NoProfile -EncodedCommand $enc
```
For ATT&CK-aligned test cases use [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) technique **T1059.001** and **T1027.010**, still inside the VM.

## 5. Export and triage
```powershell
wevtutil qe Microsoft-Windows-Sysmon/Operational /q:"*[System[(EventID=1)]]" /f:xml /c:500 > sysmon.xml
wevtutil qe Microsoft-Windows-PowerShell/Operational /q:"*[System[(EventID=4104)]]" /f:xml /c:500 > ps4104.xml
```
```bash
psunmask triage sysmon.xml --markdown report.md --json report.json
psunmask triage ps4104.xml
```
