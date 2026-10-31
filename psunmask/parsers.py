"""Telemetry readers: Sysmon 1, Security 4688, PowerShell 4104, .evtx, plain text.

Windows event XML (wevtutil qe ... /f:xml, or Event Viewer "Save as XML") is read with
defusedxml-style hygiene: DTDs are rejected, nothing is resolved from the network.
"""
from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from collections import defaultdict
from pathlib import Path
from typing import Dict, Iterator, List

from .models import Event

NS = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}


def _wrap(xml_text: str) -> ET.Element:
    if "<!DOCTYPE" in xml_text or "<!ENTITY" in xml_text:
        raise ValueError("DTD/entities are not allowed in event XML")
    xml_text = re.sub(r"<\?xml[^>]*\?>", "", xml_text)
    return ET.fromstring(f"<Events>{xml_text}</Events>")


def _data(ev: ET.Element) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for d in ev.findall("e:EventData/e:Data", NS):
        if d.get("Name"):
            out[d.get("Name")] = d.text or ""
    return out


def _system(ev: ET.Element) -> Dict[str, str]:
    eid = ev.find("e:System/e:EventID", NS)
    comp = ev.find("e:System/e:Computer", NS)
    tc = ev.find("e:System/e:TimeCreated", NS)
    return {
        "id": (eid.text or "") if eid is not None else "",
        "host": (comp.text or "") if comp is not None else "",
        "time": tc.get("SystemTime", "") if tc is not None else "",
    }


def parse_event_xml(xml_text: str) -> List[Event]:
    root = _wrap(xml_text)
    events: List[Event] = []
    blocks: Dict[str, List[tuple]] = defaultdict(list)
    meta: Dict[str, Event] = {}
    for ev in root.iter("{%s}Event" % NS["e"]):
        s, d = _system(ev), _data(ev)
        eid = int(s["id"]) if s["id"].isdigit() else None
        if eid == 1:  # Sysmon process create
            events.append(Event("sysmon", 1, d.get("UtcTime", s["time"]), s["host"], d.get("User", ""),
                                d.get("Image", ""), d.get("CommandLine", ""),
                                d.get("ParentImage", ""), d.get("ParentCommandLine", "")))
        elif eid == 4688:  # Security process creation (needs command-line auditing)
            events.append(Event("security-4688", 4688, s["time"], s["host"], d.get("SubjectUserName", ""),
                                d.get("NewProcessName", ""), d.get("CommandLine", ""),
                                d.get("ParentProcessName", "")))
        elif eid == 4104:  # PowerShell script block logging (multi-part)
            sid = d.get("ScriptBlockId", f"anon-{len(blocks)}")
            blocks[sid].append((int(d.get("MessageNumber", "1") or 1), d.get("ScriptBlockText", "")))
            meta.setdefault(sid, Event("ps-4104", 4104, s["time"], s["host"], "", "powershell.exe"))
    for sid, parts in blocks.items():
        e = meta[sid]
        e.script_block = "".join(text for _, text in sorted(parts))
        events.append(e)
    return events


def parse_text(text: str) -> List[Event]:
    return [Event("text", None, command_line=line.strip())
            for line in text.splitlines() if line.strip() and not line.lstrip().startswith("#")]


def _evtx_to_xml(path: Path) -> str:
    try:
        from Evtx.Evtx import Evtx  # type: ignore
    except ImportError as exc:  # pragma: no cover
        raise SystemExit("EVTX support needs: pip install 'psunmask[evtx]'") from exc
    with Evtx(str(path)) as log:  # pragma: no cover
        return "\n".join(rec.xml() for rec in log.records())


def iter_events(path: str, fmt: str = "auto") -> Iterator[Event]:
    p = Path(path)
    if fmt == "auto":
        fmt = {".evtx": "evtx", ".xml": "xml"}.get(p.suffix.lower(), "text")
    if fmt == "evtx":
        yield from parse_event_xml(_evtx_to_xml(p))
    elif fmt in ("xml", "sysmon", "4104"):
        yield from parse_event_xml(p.read_text(encoding="utf-8", errors="replace"))
    else:
        yield from parse_text(p.read_text(encoding="utf-8", errors="replace"))
