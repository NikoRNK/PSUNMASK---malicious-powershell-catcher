"""Layer-by-layer static deobfuscation.

Each *step* takes the current text and returns a new text if it managed to peel
something off (or None). The loop runs until nothing changes or MAX_DEPTH is hit.
No step evaluates PowerShell: everything is regex + Base64 + decompression.
"""
from __future__ import annotations

import hashlib
import re
from typing import Callable, List, Optional

from .decoder import (
    BARE_B64_RE,
    ENC_FLAG_RE,
    b64decode_lenient,
    bytes_to_text,
    inflate_any,
    looks_like_text,
    magic_kind,
)
from .models import Artifact, Layer, UnmaskResult

MAX_DEPTH = 10

_B64_CALL_RE = re.compile(
    r"FromBase64String\(\s*(['\"])([A-Za-z0-9+/=\s]{16,})\1\s*\)", re.IGNORECASE
)
_CONCAT_RE = re.compile(r"(['\"])([^'\"\r\n]*)\1\s*\+\s*(['\"])([^'\"\r\n]*)\3")
_CHAR_RUN_RE = re.compile(
    r"((?:\(?\[char\]\s*\(?\d{1,5}\)?\)?\s*\+\s*)+\(?\[char\]\s*\(?\d{1,5}\)?\)?)", re.IGNORECASE
)
_CHAR_ARRAY_RE = re.compile(
    r"\(?\[char\[\]\]\s*\(?\s*((?:\d{1,5}\s*,\s*)+\d{1,5})\s*\)?\)?\s*-join\s*(?:''|\"\")",
    re.IGNORECASE,
)
_TICK_RE = re.compile(r"`([A-Za-z])")
_ESCAPES = "0abefnrtuv"

Step = Callable[[str, List[Artifact]], Optional[str]]


def _quote(chars: str) -> str:
    return "'" + chars.replace("'", "''") + "'"


def step_backticks(text: str, _: List[Artifact]) -> Optional[str]:
    """I`E`X -> IEX. Only when the backtick density looks like obfuscation."""
    if len(_TICK_RE.findall(text)) < 2:
        return None
    new = _TICK_RE.sub(lambda m: m.group(0) if m.group(1) in _ESCAPES else m.group(1), text)
    return new if new != text else None


def step_char_codes(text: str, _: List[Artifact]) -> Optional[str]:
    """[char]73+[char]69+[char]88 and ([char[]](73,69,88) -join '') -> 'IEX'."""

    def to_str(m: "re.Match[str]") -> str:
        return _quote("".join(chr(int(n)) for n in re.findall(r"\d{1,5}", m.group(1))))

    new = _CHAR_ARRAY_RE.sub(to_str, _CHAR_RUN_RE.sub(to_str, text))
    return new if new != text else None


def step_concat(text: str, _: List[Artifact]) -> Optional[str]:
    """'Down'+'loadString' -> 'DownloadString' (repeated until stable)."""
    current = text
    for _i in range(500):
        new = _CONCAT_RE.sub(
            lambda m: m.group(1) + m.group(2) + m.group(4) + m.group(1), current, count=1
        )
        if new == current:
            break
        current = new
    return current if current != text else None


def step_encoded_command(text: str, _: List[Artifact]) -> Optional[str]:
    """powershell -enc <base64 UTF-16LE> (or a bare Base64 blob)."""
    candidates = [m.group(1) for m in ENC_FLAG_RE.finditer(text)]
    stripped = text.strip()
    if not candidates and BARE_B64_RE.fullmatch(stripped):
        candidates = [stripped]
    for blob in candidates:
        raw = b64decode_lenient(blob)
        if raw:
            decoded = bytes_to_text(raw)
            if looks_like_text(decoded):
                return decoded
    return None


def step_base64_blobs(text: str, artifacts: List[Artifact]) -> Optional[str]:
    """[Convert]::FromBase64String('...') optionally wrapped in Deflate/Gzip streams."""
    parts: List[str] = []
    for m in _B64_CALL_RE.finditer(text):
        raw = b64decode_lenient(m.group(2))
        if not raw:
            continue
        data = inflate_any(raw) or raw
        decoded = bytes_to_text(data)
        if looks_like_text(decoded):
            parts.append(decoded)
        else:
            digest = hashlib.sha256(data).hexdigest()
            if all(a.sha256 != digest for a in artifacts):
                artifacts.append(Artifact(magic_kind(data), len(data), digest))
    return "\n".join(parts) if parts else None


# Order matters: normalise strings first so Base64 split across concatenations reassembles.
_STEPS = [
    ("backtick removal", step_backticks),
    ("[char] code resolution", step_char_codes),
    ("string concatenation merge", step_concat),
    ("-EncodedCommand / Base64 (UTF-16LE)", step_encoded_command),
    ("FromBase64String (+ inflate)", step_base64_blobs),
]


def unmask(text: str) -> UnmaskResult:
    """Peel every layer we can recognise. Pure function, no side effects."""
    layers = [Layer(0, "original", text)]
    artifacts: List[Artifact] = []
    current = text
    for _round in range(MAX_DEPTH):
        progressed = False
        for name, step in _STEPS:
            new = step(current, artifacts)
            if new and new != current:
                current = new
                layers.append(Layer(len(layers), name, current))
                progressed = True
                if len(layers) > MAX_DEPTH * 2:
                    return UnmaskResult(layers, artifacts)
        if not progressed:
            break
    return UnmaskResult(layers, artifacts)
