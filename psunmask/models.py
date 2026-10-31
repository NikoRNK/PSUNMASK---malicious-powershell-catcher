"""Plain data containers shared across the pipeline."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Layer:
    """One step of the unwrapping chain (layer 0 is the untouched input)."""

    depth: int
    technique: str
    text: str


@dataclass
class Artifact:
    """A decoded blob that is not text (PE, shellcode...). Only metadata is kept."""

    kind: str
    size: int
    sha256: str


@dataclass
class UnmaskResult:
    layers: List[Layer]
    artifacts: List[Artifact] = field(default_factory=list)

    @property
    def final(self) -> str:
        return self.layers[-1].text

    @property
    def depth(self) -> int:
        return len(self.layers) - 1


@dataclass
class Hit:
    rule_id: str
    title: str
    tactic: str
    technique: str
    weight: int
    layer: int
    evidence: str
    description: str


@dataclass
class Event:
    """Normalised telemetry record (Sysmon 1, Security 4688, PowerShell 4104, text)."""

    source: str
    event_id: Optional[int] = None
    time: str = ""
    host: str = ""
    user: str = ""
    image: str = ""
    command_line: str = ""
    parent_image: str = ""
    parent_command_line: str = ""
    script_block: str = ""

    @property
    def payload(self) -> str:
        return self.script_block or self.command_line
