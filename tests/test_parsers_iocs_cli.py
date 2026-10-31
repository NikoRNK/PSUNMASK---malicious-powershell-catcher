import json

from conftest import SAMPLES
from psunmask import iocs
from psunmask.analyzer import triage
from psunmask.cli import main
from psunmask.parsers import iter_events, parse_event_xml


def test_sysmon_sample_filters_to_powershell_and_ranks():
    findings = triage(iter_events(str(SAMPLES / "sysmon_event1.xml")))
    assert len(findings) == 3  # notepad ignored
    assert findings[0].score >= findings[-1].score
    assert {f.verdict for f in findings} == {"MALICIOUS", "LIKELY_BENIGN"}


def test_4104_blocks_are_reassembled_in_order():
    events = list(iter_events(str(SAMPLES / "scriptblock_4104.xml")))
    assert len(events) == 1
    assert events[0].script_block.startswith("$c = 'Down'") and "schtasks" in events[0].script_block


def test_dtd_is_rejected():
    import pytest
    with pytest.raises(ValueError):
        parse_event_xml('<!DOCTYPE x [<!ENTITY a "b">]><Event/>')


def test_ioc_extraction_and_defang():
    found = iocs.extract(["x TCPClient('c2.bad.example',4444) http://203.0.113.9/a.ps1"])
    assert "c2.bad.example" in found["domains"] and "203.0.113.9" in found["ips"]
    assert iocs.defang("http://203.0.113.9/a.ps1") == "hxxp[://]203[.]0[.]113[.]9/a[.]ps1"


def test_cli_triage_outputs_and_exit_code(tmp_path, capsys):
    md, js = tmp_path / "r.md", tmp_path / "r.json"
    rc = main(["triage", str(SAMPLES / "sysmon_event1.xml"), "--markdown", str(md), "--json", str(js),
               "--fail-on-malicious", "--no-color"])
    assert rc == 2
    assert "Call it" in md.read_text() and json.loads(js.read_text())[0]["verdict"] == "MALICIOUS"


def test_cli_decode_bare_base64(capsys):
    from conftest import enc
    assert main(["decode", enc("Get-Date"), "--no-color"]) == 0
    assert "Get-Date" in capsys.readouterr().out
