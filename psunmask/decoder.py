"""Low-level, side-effect free decoding helpers.

Everything here is *reading*: Base64 -> bytes -> text. Content is never executed.
"""
from __future__ import annotations

import base64
import binascii
import re
import zlib
from typing import Optional

# powershell.exe accepts any unambiguous prefix of -EncodedCommand (-e, -ec, -enc ...)
_PREFIXES = ["e", "ec"] + ["encodedcommand"[:i] for i in range(2, 15)]
ENC_FLAG_PATTERN = (
    r"(?<![\w-])[-/\u2013\u2014](?:"
    + "|".join(sorted(set(_PREFIXES), key=len, reverse=True))
    + r")(?![\w-])\s*[\"']?([A-Za-z0-9+/=]{8,})[\"']?"
)
ENC_FLAG_RE = re.compile(ENC_FLAG_PATTERN, re.IGNORECASE)
BARE_B64_RE = re.compile(r"[A-Za-z0-9+/]{16,}={0,2}")

MAX_OUTPUT = 10 * 1024 * 1024  # hard cap against decompression bombs


def b64decode_lenient(data: str) -> Optional[bytes]:
    """Decode Base64 tolerating whitespace and missing padding."""
    data = re.sub(r"\s+", "", data)
    if not data:
        return None
    data += "=" * (-len(data) % 4)
    try:
        return base64.b64decode(data, validate=True)
    except (binascii.Error, ValueError):
        return None


def bytes_to_text(raw: bytes) -> str:
    """Best-effort bytes -> str. UTF-16LE is the PowerShell default for -enc."""
    if raw[:2] == b"\xff\xfe":
        return raw[2:].decode("utf-16-le", errors="replace")
    if raw[:3] == b"\xef\xbb\xbf":
        return raw[3:].decode("utf-8", errors="replace")
    if len(raw) >= 4 and raw[1::2].count(0) >= 0.8 * (len(raw) // 2):
        return raw[: len(raw) // 2 * 2].decode("utf-16-le", errors="replace")
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return raw.decode("latin-1")


def looks_like_text(text: str) -> bool:
    if not text or "\x00" in text:
        return False
    printable = sum(1 for c in text if c.isprintable() or c in "\r\n\t")
    return printable / len(text) >= 0.9


def _inflate(raw: bytes, wbits: int) -> Optional[bytes]:
    decomp = zlib.decompressobj(wbits)
    try:
        out = decomp.decompress(raw, MAX_OUTPUT)
    except zlib.error:
        return None
    if decomp.unconsumed_tail or not out:  # bomb guard / empty
        return None
    return out


def inflate_any(raw: bytes) -> Optional[bytes]:
    """Try gzip, zlib and raw DEFLATE (what System.IO.Compression.DeflateStream emits)."""
    for wbits in (31, 15, -15):
        out = _inflate(raw, wbits)
        if out is not None:
            return out
    return None


def magic_kind(raw: bytes) -> str:
    if raw[:2] == b"MZ":
        return "PE executable (MZ header)"
    if raw[:4] == b"\x7fELF":
        return "ELF executable"
    if raw[:2] == b"PK":
        return "ZIP archive"
    return "binary blob (possible shellcode)"
