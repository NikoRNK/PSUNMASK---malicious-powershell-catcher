# From analysis to detection

Every decoded sample should end with a detection, otherwise the work only helped once.

| Observation during triage | Detection idea | Artifact in this repo |
|---|---|---|
| Encoded command from unusual parent | Process creation with `-enc` minus allow-listed parents | `rules/powershell_encoded_command.yml` |
| Office / script host starts PowerShell | Parent-child relationship | `rules/office_spawns_powershell.yml` |
| Decoded script has IEX + download | Script Block Logging content match (works after decoding) | `rules/scriptblock_download_cradle.yml` |
| Same IOC on several hosts | Hunt by hash, URL, domain | `detections/splunk.spl`, `detections/kql.kql` |

## Tuning checklist
1. Run the rule over 30 days of history, count hits per host and parent.
2. Allow-list by **parent process + signed script path**, never by command text alone.
3. Keep a high-severity variant (Office parent, hidden window, cradle) separate from the noisy generic one.
4. Re-test after every change with the bundled samples (`samples/`) and your lab telemetry.

## Convert Sigma to your SIEM
```bash
pip install sigma-cli
sigma convert -t splunk -p sysmon rules/office_spawns_powershell.yml
sigma convert -t microsoft365defender rules/powershell_encoded_command.yml
```

## Limits of command-line detections
Attackers can avoid `-enc` entirely (download then run, `-Command` with obfuscated strings, `pwsh` renamed binaries). Script Block Logging plus AMSI telemetry is the layer that still sees the deobfuscated content, which is why PSUnmask treats 4104 as a first-class source.
