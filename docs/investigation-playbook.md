# Investigation playbook: suspicious PowerShell

Four steps, same order every time: **Catch it, Decode it, Trace it, Call it.**
The golden rule: **decoding is reading. Never run the command.**

## 1. Catch it

| Source | What you get | Notes |
|---|---|---|
| Sysmon Event ID 1 | Image, full CommandLine, ParentImage, ParentCommandLine, hashes, user | Needs a Sysmon config that does not filter powershell.exe |
| Security 4688 | NewProcessName, CommandLine, ParentProcessName | Enable *Include command line in process creation events* |
| PowerShell 4104 | The script block **after** PowerShell decoded `-enc` | Enable Script Block Logging; long scripts are split in parts (MessageNumber / MessageTotal) |
| EDR telemetry | Same as above plus process tree | Export to XML/JSON for PSUnmask |

Triage questions: which host and user? what time (business hours?) what is the command length (very long = blob)? which flags (`-nop -w hidden -enc` is the classic trio)?

## 2. Decode it

Typical obfuscation stack, outermost first:

1. `-EncodedCommand` = Base64 of **UTF-16LE** text (CyberChef: *From Base64* then *Decode text UTF-16LE (1200)*)
2. `[Convert]::FromBase64String` + `DeflateStream` / `GzipStream` = another compressed Base64 layer
3. String tricks: `'Down'+'loadString'`, backticks `I`E`X`, `[char]73+[char]69+[char]88`
4. Final stage is usually a cradle: `IEX (New-Object Net.WebClient).DownloadString(url)`

`psunmask decode` automates 1 to 3 and keeps every intermediate layer so you can show your work. Manual fallback: CyberChef, in an isolated analysis VM, copy-paste only.

## 3. Trace it

The parent process tells the real story.

| Parent | Reading |
|---|---|
| `WINWORD.EXE`, `EXCEL.EXE`, `OUTLOOK.EXE` | Document or mail lure, macro or exploit. Treat as hostile until proven otherwise |
| `wscript.exe`, `cscript.exe`, `mshta.exe` | Script-based loader (JS/VBS/HTA), often from a download or archive |
| `wmiprvse.exe` | Remote WMI execution, think lateral movement |
| `w3wp.exe` | Web server worker, think web shell |
| `CcmExec.exe`, Intune agent | Usually management tooling. Verify the script source |
| `explorer.exe` | User double-clicked something (LNK, shortcut). Look at the grandparent and file creation events |

Pivots: process tree up and down, network connections (Sysmon 3, DNS 22) from the same ProcessGuid, file creation (Sysmon 11), registry persistence (Sysmon 13), other hosts that ran the same command hash.

## 4. Call it

**Malicious or admin, with evidence.** Write the verdict and the evidence that supports it.

| Verdict | Evidence examples | Action |
|---|---|---|
| Malicious | Cradle + hidden + Office parent; AMSI bypass; known-bad IOC; LSASS access | Contain host, block IOCs, scope, escalate to IR |
| Suspicious | Encoded + hidden but unknown tooling; rare script, no network IOC | Contact owner, collect script source, keep ticket open |
| Benign / admin | Inventory or patch script, signed script path, management parent, owner confirms | Close with the decoded command attached, tune detection |

A good ticket contains: raw command, decoded script, layer chain, IOCs (defanged), process tree, MITRE techniques, verdict, and next action. `psunmask triage --markdown` generates exactly that.
