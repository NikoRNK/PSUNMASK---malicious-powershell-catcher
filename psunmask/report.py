"""Output: console (ANSI), Markdown incident note, JSON."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import List

from .analyzer import Finding
from .iocs import defang

COLORS = {"MALICIOUS": "\033[1;31m", "SUSPICIOUS": "\033[1;33m", "LIKELY_BENIGN": "\033[1;32m"}
RESET, DIM, BOLD = "\033[0m", "\033[2m", "\033[1m"

ACTIONS = {
    "MALICIOUS": [
        "Isolate the host (EDR network containment) and preserve volatile evidence.",
        "Block the extracted IOCs (proxy / DNS / firewall) and hunt them across the fleet.",
        "Identify the initial access vector from the parent process chain; scope other hosts and users.",
        "Reset credentials of the affected account; escalate to incident response.",
    ],
    "SUSPICIOUS": [
        "Ask the host owner / change calendar whether this automation is expected.",
        "Pull the script source (4104 logs, file on disk) and compare against known admin tooling.",
        "Check IOC reputation and prevalence; keep the alert open until a human confirms.",
    ],
    "LIKELY_BENIGN": [
        "Document the decoded command and close as admin activity, or tune the rule with an allow-list.",
    ],
}


def _short(text: str, n: int = 150) -> str:
    text = " ".join(text.split())
    return text if len(text) <= n else text[:n] + f"... (+{len(text) - n} chars)"


def _trunc(text: str, n: int) -> str:
    return text if len(text) <= n else text[:n] + f"\n... [{len(text) - n} more chars]"


def to_console(findings: List[Finding], color: bool = True, limit: int = 1200) -> str:
    c = (lambda k: COLORS.get(k, "")) if color else (lambda k: "")
    r, d, b = (RESET, DIM, BOLD) if color else ("", "", "")
    if not findings:
        return "No PowerShell activity found."
    out: List[str] = []
    for i, f in enumerate(findings, 1):
        ev = f.event
        out.append(f"{b}[{i}] {c(f.verdict)}{f.verdict}{r}{b}  score {f.score}/100{r}")
        meta = " | ".join(x for x in (ev.time, ev.host, ev.user) if x)
        if meta:
            out.append(f"{d}    {meta}{r}")
        if ev.parent_image:
            out.append(f"    parent : {ev.parent_image}")
        out.append(f"    {b}CATCH IT{r}  {_short(ev.payload)}")
        chain = " -> ".join(layer.technique for layer in f.result.layers)
        out.append(f"    {b}DECODE IT{r} {chain}")
        out.append(_indent(_trunc(f.result.final, limit), "      | "))
        out.append(f"    {b}TRACE IT{r}  " + ("; ".join(f.context) if f.context else "no parent-process signal"))
        for h in f.hits:
            out.append(f"      - {h.rule_id} {h.title} [{h.technique}] +{h.weight} (layer {h.layer})")
        if any(f.iocs.values()):
            out.append(f"    {b}IOCs (defanged){r}")
            for kind, vals in f.iocs.items():
                for v in vals:
                    out.append(f"      {kind[:-1] if kind.endswith('s') else kind}: {defang(v)}")
        out.append(f"    {b}CALL IT{r}   {c(f.verdict)}{f.verdict}{r}  sha256(final)={f.sha256[:16]}...")
        out.append("")
    return "\n".join(out)


def _indent(text: str, prefix: str) -> str:
    return "\n".join(prefix + line for line in text.splitlines())


def to_markdown(findings: List[Finding], source: str = "") -> str:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    counts = {v: sum(1 for f in findings if f.verdict == v) for v in COLORS}
    md = ["# PowerShell triage report", "", f"- Generated: {now}", f"- Source: `{source}`" if source else "",
          f"- Findings: {len(findings)} (malicious {counts['MALICIOUS']}, suspicious {counts['SUSPICIOUS']}, "
          f"likely benign {counts['LIKELY_BENIGN']})", "",
          "> Decoded content is shown for reading only. Never paste it into a terminal.", ""]
    for i, f in enumerate(findings, 1):
        ev = f.event
        md += [f"## {i}. {f.verdict} (score {f.score}/100)", "",
               "| Field | Value |", "|---|---|",
               f"| Time | {ev.time or '-'} |", f"| Host | {ev.host or '-'} |", f"| User | {ev.user or '-'} |",
               f"| Process | `{ev.image or '-'}` |", f"| Parent | `{ev.parent_image or '-'}` |",
               f"| MITRE ATT&CK | {', '.join(f.techniques) or '-'} |", f"| SHA-256 (final script) | `{f.sha256}` |", ""]
        md += ["### 1. Catch it", "", "```text", _trunc(ev.payload, 800), "```", "",
               "### 2. Decode it", "", "Layers: " + " -> ".join(f"`{layer.technique}`" for layer in f.result.layers), "",
               "```powershell", _trunc(f.result.final, 3000), "```", ""]
        md += ["### 3. Trace it", ""]
        md += [f"- {x}" for x in f.context] or ["- No parent-process signal."]
        md += [""]
        if f.hits:
            md += ["| Rule | Detection | ATT&CK | Weight | Layer |", "|---|---|---|--:|--:|"]
            md += [f"| {h.rule_id} | {h.title} | {h.technique} | {h.weight} | {h.layer} |" for h in f.hits]
            md += [""]
        if any(f.iocs.values()):
            md += ["**IOCs (defanged)**", ""]
            md += [f"- {k}: `{defang(v)}`" for k, vs in f.iocs.items() for v in vs] + [""]
        md += [f"### 4. Call it: **{f.verdict}**", ""] + [f"1. {a}" for a in ACTIONS[f.verdict]][:1]
        md += [f"{n}. {a}" for n, a in enumerate(ACTIONS[f.verdict][1:], 2)] + [""]
    return "\n".join(x for x in md if x is not None)


def to_json(findings: List[Finding]) -> str:
    return json.dumps([f.to_dict() for f in findings], indent=2, ensure_ascii=False)
