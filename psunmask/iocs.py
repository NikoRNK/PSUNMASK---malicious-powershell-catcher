"""Indicator extraction and defanging."""
from __future__ import annotations

import re
from typing import Dict, Iterable, List
from urllib.parse import urlparse

URL_RE = re.compile(r"\b(?:https?|ftp)://[^\s'\"<>)\]}]+", re.IGNORECASE)
IPV4_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b")
TCP_RE = re.compile(r"TCPClient\(\s*['\"]([^'\"]+)['\"]\s*,\s*(\d{1,5})", re.IGNORECASE)
REG_RE = re.compile(r"\bHK(?:LM|CU|CR|U|CC)(?::|\\)\\?[^\s'\"]+|\bHKEY_[A-Z_]+\\[^\s'\"]+", re.IGNORECASE)
PATH_RE = re.compile(r"\b[A-Za-z]:\\(?:[^\s'\"<>|:*?]+\\)*[^\s'\"<>|:*?\\]+|\\\\[\w.$-]+\\[^\s'\"]+")


def _uniq(items: Iterable[str]) -> List[str]:
    return sorted({i.rstrip(".,;") for i in items})


def extract(texts: Iterable[str]) -> Dict[str, List[str]]:
    blob = "\n".join(texts)
    urls = _uniq(URL_RE.findall(blob))
    ips = _uniq(IPV4_RE.findall(blob))
    domains = {urlparse(u).hostname or "" for u in urls}
    for host, port in TCP_RE.findall(blob):
        domains.add(host)
        urls.append(f"tcp://{host}:{port}")
    domains = {d for d in domains if d and not IPV4_RE.fullmatch(d)}
    return {
        "urls": _uniq(urls),
        "ips": ips,
        "domains": sorted(domains),
        "registry": _uniq(REG_RE.findall(blob)),
        "paths": _uniq(PATH_RE.findall(blob)),
    }


def defang(value: str) -> str:
    value = re.sub(r"^(h)(tt)p", r"\1xxp", value, flags=re.IGNORECASE)
    value = value.replace("://", "[://]") if value.lower().startswith(("hxxp", "ftp", "tcp")) else value
    return re.sub(r"\.(?=[A-Za-z0-9])", "[.]", value)
