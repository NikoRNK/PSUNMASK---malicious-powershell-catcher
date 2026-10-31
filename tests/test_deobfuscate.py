import base64
import zlib

from conftest import enc
from psunmask.deobfuscate import MAX_DEPTH, unmask


def test_encoded_command_is_decoded():
    assert unmask(f"powershell -enc {enc('Get-Date')}").final == "Get-Date"


def test_concat_backtick_and_char_codes():
    r = unmask("('Down'+'load'+'String') I`E`X ([char]73+[char]69+[char]88)")
    assert "'DownloadString'" in r.final and "IEX" in r.final and "'IEX'" in r.final


def test_char_array_join():
    assert "'IEX'" in unmask("([char[]](73,69,88) -join '')").final


def test_deflate_layer():
    c = zlib.compressobj(9, zlib.DEFLATED, -15)
    blob = base64.b64encode(c.compress(b"Write-Host hello-from-layer-2") + c.flush()).decode()
    r = unmask(f"IEX ([Convert]::FromBase64String('{blob}'))")
    assert "hello-from-layer-2" in r.final


def test_nested_encoded_layers_and_depth_limit():
    script = "Write-Host deep"
    for _ in range(3):
        script = f"powershell -enc {enc(script)}"
    r = unmask(script)
    assert r.final == "Write-Host deep" and r.depth == 3
    # a self-referencing pathological input must terminate
    assert unmask("'a'+'b' " * 2000).depth <= MAX_DEPTH * 2


def test_binary_payload_becomes_artifact_not_text():
    pe = b"MZ" + bytes(range(256)) * 4
    r = unmask(f"[Convert]::FromBase64String('{base64.b64encode(pe).decode()}')")
    assert r.artifacts and "PE" in r.artifacts[0].kind and len(r.artifacts[0].sha256) == 64


def test_plain_text_is_left_alone():
    r = unmask("Get-ChildItem C:\\Temp")
    assert r.depth == 0
