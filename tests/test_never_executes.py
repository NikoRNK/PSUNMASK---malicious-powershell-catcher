"""Guard rail: this tool analyses hostile content, so the package must never contain
code paths that execute or dynamically evaluate anything."""
import ast
from pathlib import Path

FORBIDDEN_NAMES = {"exec", "eval", "compile", "__import__"}  # bare builtins (re.compile is fine)
FORBIDDEN_ATTRS = {"system", "popen", "Popen", "run", "call", "check_output"}
FORBIDDEN_IMPORTS = {"subprocess", "ctypes", "pickle", "marshal"}


def test_no_execution_primitives():
    for path in Path(__file__).resolve().parent.parent.joinpath("psunmask").glob("*.py"):
        tree = ast.parse(path.read_text())
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                assert not FORBIDDEN_IMPORTS & {a.name.split(".")[0] for a in node.names}, path
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] not in FORBIDDEN_IMPORTS, path
            if isinstance(node, ast.Call):
                if isinstance(node.func, ast.Name):
                    assert node.func.id not in FORBIDDEN_NAMES, f"{path}: {node.func.id}()"
                elif isinstance(node.func, ast.Attribute):
                    assert node.func.attr not in FORBIDDEN_ATTRS, f"{path}: .{node.func.attr}()"
