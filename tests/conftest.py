import base64
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()
