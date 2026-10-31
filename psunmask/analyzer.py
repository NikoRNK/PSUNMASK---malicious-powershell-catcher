"""Scoring, verdict and context enrichment: the CALL IT step."""
from __future__ import annotations

import hashlib
import ntpath
from dataclasses import dataclass, field
from typing import Dict, List

from . import iocs as ioc_mod
from .deobfuscate import unmask
from .models import Event, Hit, UnmaskResult
from .rules import BENIGN_PARENTS, RULES, SUSPICIOUS_PARENTS

MALICIOUS_AT = 50
SUSPICIOUS_AT = 20


@dataclass
class Finding:
    event: Event
    result: UnmaskResult
    hits: List[Hit]
    context: List[str]
    iocs: Dict[str, List[str]]
    score: int
    verdict: str
    sha256: str
    techniques: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "verdict": self.verdict,
            "score": self.score,
            "event": vars(self.event),
            "layers": [{"depth": layer.depth, "technique": layer.technique, "text": layer.text} for layer in self.result.layers],
            "artifacts": [vars(a) for a in self.result.artifacts],
            "hits": [vars(h) for h in self.hits],
            "context": self.context,
            "iocs": self.iocs,
            "iocs_defanged": {k: [ioc_mod.defang(v) for v in vs] for k, vs in self.iocs.items()},
            "mitre": self.techniques,
            "sha256_final": self.sha256,
        }


def _snippet(text: str, start: int, end: int, width: int = 90) -> str:
    s = text[max(0, start - 15): min(len(text), end + 40)].replace("\n", " ")
    return (s[:width] + "...") if len(s) > width else s


def analyse(event: Event) -> Finding:
    result = unmask(event.payload)
    hits: List[Hit] = []
    for rule in RULES:
        for layer in result.layers:
            m = rule.pattern.search(layer.text)
            if m:
                hits.append(Hit(rule.id, rule.title, rule.tactic, rule.technique, rule.weight, layer.depth,
                                _snippet(layer.text, m.start(), m.end()), rule.description))
                break  # one hit per rule, earliest layer

    score = sum(h.weight for h in hits)
    context: List[str] = []
    techniques = {h.technique for h in hits}

    parent = ntpath.basename(event.parent_image).lower()
    if parent in SUSPICIOUS_PARENTS:
        weight, tech, note = SUSPICIOUS_PARENTS[parent]
        score += weight
        techniques.add(tech)
        context.append(f"+{weight} parent {parent}: {note}")
    elif parent in BENIGN_PARENTS:
        score -= 15
        context.append(f"-15 parent {parent} ({BENIGN_PARENTS[parent]}): usual for legitimate automation, verify script origin")

    if result.depth >= 3:
        score += 10
        context.append(f"+10 {result.depth} obfuscation layers peeled")
    if result.artifacts:
        score += 20
        context.append("+20 non-text payload decoded: " + ", ".join(f"{a.kind} {a.size}B" for a in result.artifacts))

    score = max(0, min(100, score))
    verdict = "MALICIOUS" if score >= MALICIOUS_AT else "SUSPICIOUS" if score >= SUSPICIOUS_AT else "LIKELY_BENIGN"
    texts = [layer.text for layer in result.layers]
    return Finding(event, result, hits, context, ioc_mod.extract(texts), score, verdict,
                   hashlib.sha256(result.final.encode("utf-8", "replace")).hexdigest(), sorted(techniques))


def is_powershell(event: Event) -> bool:
    blob = f"{event.image} {event.command_line}".lower()
    return event.source in ("ps-4104", "text") or "powershell" in blob or "pwsh" in blob


def triage(events, min_score: int = 0) -> List[Finding]:
    findings = [analyse(e) for e in events if is_powershell(e)]
    findings = [f for f in findings if f.score >= min_score]
    return sorted(findings, key=lambda f: f.score, reverse=True)
