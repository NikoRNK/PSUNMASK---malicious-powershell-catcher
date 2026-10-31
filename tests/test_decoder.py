import pytest

from conftest import enc
from psunmask.decoder import ENC_FLAG_RE, b64decode_lenient, bytes_to_text, inflate_any


@pytest.mark.parametrize("flag", ["-e", "-ec", "-en", "-enc", "-EncodedCommand", "-ENCODEDCOMMAND", "/enc"])
def test_flag_variants_match(flag):
    m = ENC_FLAG_RE.search(f"powershell.exe {flag} {enc('whoami')}")
    assert m and bytes_to_text(b64decode_lenient(m.group(1))) == "whoami"


@pytest.mark.parametrize("cmd", [
    "powershell -ExecutionPolicy Bypass -File a.ps1",
    "powershell -ep bypass -command whoami",
    "powershell -NoExit -Command dir",
])
def test_other_e_flags_do_not_match(cmd):
    assert ENC_FLAG_RE.search(cmd) is None


def test_padding_and_whitespace_tolerated():
    blob = enc("hi")
    assert b64decode_lenient(blob.rstrip("=")) == b64decode_lenient(blob)
    assert b64decode_lenient(" \n".join(blob[i:i + 4] for i in range(0, len(blob), 4)))


def test_invalid_base64_returns_none():
    assert b64decode_lenient("!!!not base64!!!") is None


def test_inflate_rejects_garbage():
    assert inflate_any(b"definitely not compressed") is None
