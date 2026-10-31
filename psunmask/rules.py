"""Detection rules mapped to MITRE ATT&CK.

Each rule is a case-insensitive regex run against *every* unmasked layer, so a
cradle hidden three Base64 layers deep is still caught. Weights are additive and
capped at 100 by the analyzer. Tune them to your environment.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from typing import List

from .decoder import ENC_FLAG_PATTERN


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: "re.Pattern[str]"
    weight: int
    tactic: str
    technique: str
    description: str


def _r(id_: str, title: str, pattern: str, weight: int, tactic: str, technique: str, desc: str) -> Rule:
    return Rule(id_, title, re.compile(pattern, re.IGNORECASE), weight, tactic, technique, desc)


RULES: List[Rule] = [
    _r("PS001", "Encoded command", ENC_FLAG_PATTERN, 10,
       "Defense Evasion", "T1027.010",
       "Command passed as Base64 (-enc). Common in malware, also in legitimate management tools."),
    _r("PS002", "Invoke-Expression", r"\b(?:iex|invoke-expression)\b", 20,
       "Execution", "T1059.001",
       "Evaluates a string as code; the core of most fileless cradles."),
    _r("PS003", "Download cradle", 
       r"downloadstring|downloadfile|downloaddata|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b"
       r"|net\.webclient|start-bitstransfer|system\.net\.http\.httpclient|bitsadmin",
       30, "Command and Control", "T1105",
       "Pulls a second stage from the network."),
    _r("PS004", "Hidden window", r"-w\w*\s+(?:hidden|h)\b", 15,
       "Defense Evasion", "T1564.003",
       "Runs without a visible console window."),
    _r("PS005", "NoProfile / NonInteractive", r"-nop(?:rofile)?\b|-noni(?:nteractive)?\b", 5,
       "Execution", "T1059.001",
       "Skips profile scripts; typical of scripted launchers."),
    _r("PS006", "Execution policy bypass", r"-(?:ep|exec\w*)\s+(?:bypass|unrestricted)", 10,
       "Defense Evasion", "T1059.001",
       "Overrides the execution policy for this session."),
    _r("PS007", "AMSI bypass", r"amsiutils|amsiinitfailed|amsiscanbuffer|amsicontext", 40,
       "Defense Evasion", "T1562.001",
       "Tampers with the Antimalware Scan Interface before the real payload runs."),
    _r("PS008", "Reflective / in-memory loading",
       r"reflection\.assembly\]?::load|\[reflection\.assembly\]|virtualalloc|virtualprotect|createthread"
       r"|marshal\]::(?:copy|getdelegateforfunctionpointer)|add-type[^\n]{0,200}dllimport",
       25, "Defense Evasion", "T1620",
       "Loads or runs code directly from memory (shellcode, .NET assemblies)."),
    _r("PS009", "Credential dumping", r"invoke-mimikatz|sekurlsa|lsass|minidump|comsvcs\.dll|procdump|ntds\.dit",
       50, "Credential Access", "T1003.001",
       "References LSASS / Mimikatz / NTDS dumping."),
    _r("PS010", "Scheduled task persistence",
       r"schtasks(?:\.exe)?\s+/create|register-scheduledtask|new-scheduledtask",
       25, "Persistence", "T1053.005", "Creates a scheduled task."),
    _r("PS011", "Run key persistence", r"currentversion\\run|new-service|register-wmievent|__eventfilter",
       25, "Persistence", "T1547.001", "Autostart registry key, service or WMI subscription."),
    _r("PS012", "Defender tampering",
       r"set-mppreference|add-mppreference|disablerealtimemonitoring|disableioavprotection|exclusionpath|tamperprotection",
       40, "Defense Evasion", "T1562.001", "Disables or weakens Microsoft Defender."),
    _r("PS013", "Raw socket / reverse shell", r"net\.sockets\.(?:tcpclient|tcplistener|udpclient)",
       45, "Command and Control", "T1095", "Opens a raw network socket from PowerShell."),
    _r("PS014", "Inhibit system recovery",
       r"vssadmin(?:\.exe)?\s+delete\s+shadows|win32_shadowcopy|wbadmin\s+delete|bcdedit[^\n]*recoveryenabled",
       50, "Impact", "T1490", "Deletes shadow copies / disables recovery (ransomware prep)."),
    _r("PS015", "Staged / compressed payload", r"frombase64string|deflatestream|gzipstream|memorystream",
       10, "Defense Evasion", "T1027", "Base64 and compression streams used to hide a payload."),
    _r("PS016", "WMI remote execution",
       r"win32_process[^\n]{0,80}create|invoke-wmimethod|invoke-cimmethod",
       20, "Execution", "T1047", "Starts processes through WMI/CIM."),
    _r("PS017", "Exfiltration primitives",
       r"uploadstring|uploadfile|uploaddata|compress-archive|invoke-restmethod[^\n]*-method\s+post",
       25, "Exfiltration", "T1041", "Sends or stages data for exfiltration."),
]

# Parent process context ("the parent process tells the real story").
SUSPICIOUS_PARENTS = {
    "winword.exe": (30, "T1204.002", "Office document spawned PowerShell (macro / exploit)"),
    "excel.exe": (30, "T1204.002", "Office document spawned PowerShell (macro / exploit)"),
    "powerpnt.exe": (30, "T1204.002", "Office document spawned PowerShell"),
    "outlook.exe": (30, "T1204.002", "Mail client spawned PowerShell"),
    "onenote.exe": (30, "T1204.002", "OneNote spawned PowerShell"),
    "mshta.exe": (25, "T1218.005", "mshta spawned PowerShell"),
    "wscript.exe": (25, "T1059.005", "Windows Script Host spawned PowerShell"),
    "cscript.exe": (25, "T1059.005", "Windows Script Host spawned PowerShell"),
    "regsvr32.exe": (25, "T1218.010", "regsvr32 spawned PowerShell"),
    "rundll32.exe": (25, "T1218.011", "rundll32 spawned PowerShell"),
    "wmiprvse.exe": (25, "T1047", "WMI provider host spawned PowerShell (remote WMI exec)"),
    "w3wp.exe": (40, "T1505.003", "IIS worker spawned PowerShell (possible web shell)"),
}
BENIGN_PARENTS = {
    "ccmexec.exe": "SCCM client",
    "intunemanagementextension.exe": "Intune agent",
    "microsoft.management.services.intunewindowsagent.exe": "Intune agent",
}


def rules_as_markdown() -> str:
    lines = ["| ID | Detection | Weight | Tactic | ATT&CK |", "|----|-----------|-------:|--------|--------|"]
    for r in RULES:
        lines.append(
            f"| {r.id} | {r.title} | {r.weight} | {r.tactic} | "
            f"[{r.technique}](https://attack.mitre.org/techniques/{r.technique.replace('.', '/')}/) |"
        )
    return "\n".join(lines)
