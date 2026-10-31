"""Command line interface: decode | triage | rules."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import __version__
from .analyzer import analyse, triage
from .models import Event
from .parsers import iter_events
from .report import to_console, to_json, to_markdown
from .rules import RULES, rules_as_markdown


def _read_input(value: str, from_file: bool) -> str:
    if value == "-":
        return sys.stdin.read()
    if from_file:
        return Path(value).read_text(encoding="utf-8", errors="replace")
    return value


def cmd_decode(args: argparse.Namespace) -> int:
    text = _read_input(args.input, args.file).strip()
    finding = analyse(Event("cli", command_line=text, parent_image=args.parent or ""))
    if args.json:
        print(to_json([finding]))
    else:
        print(to_console([finding], color=not args.no_color and sys.stdout.isatty()))
    return 2 if finding.verdict == "MALICIOUS" else 0


def cmd_triage(args: argparse.Namespace) -> int:
    findings = triage(iter_events(args.path, args.format), min_score=args.min_score)
    if args.json:
        Path(args.json).write_text(to_json(findings), encoding="utf-8")
    if args.markdown:
        Path(args.markdown).write_text(to_markdown(findings, args.path), encoding="utf-8")
    print(to_console(findings, color=not args.no_color and sys.stdout.isatty()))
    return 2 if any(f.verdict == "MALICIOUS" for f in findings) and args.fail_on_malicious else 0


def cmd_rules(args: argparse.Namespace) -> int:
    if args.markdown:
        print(rules_as_markdown())
    else:
        for r in RULES:
            print(f"{r.id}  {r.technique:<10} w={r.weight:<3} {r.title}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="psunmask", description="Static PowerShell deobfuscation and triage. Never executes anything.")
    p.add_argument("--version", action="version", version=f"psunmask {__version__}")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("decode", help="unwrap one command line / script / Base64 blob")
    d.add_argument("input", help="command line, Base64 blob, file path (with -f) or '-' for stdin")
    d.add_argument("-f", "--file", action="store_true", help="treat input as a file path")
    d.add_argument("--parent", help="parent process image, e.g. WINWORD.EXE (adds context score)")
    d.add_argument("--json", action="store_true")
    d.add_argument("--no-color", action="store_true")
    d.set_defaults(func=cmd_decode)

    t = sub.add_parser("triage", help="triage a Sysmon / 4688 / 4104 export (.xml, .evtx) or a text file")
    t.add_argument("path")
    t.add_argument("--format", choices=["auto", "xml", "evtx", "text"], default="auto")
    t.add_argument("--min-score", type=int, default=0)
    t.add_argument("--json", metavar="FILE", help="write full JSON results")
    t.add_argument("--markdown", metavar="FILE", help="write a Markdown incident note")
    t.add_argument("--fail-on-malicious", action="store_true", help="exit 2 if a MALICIOUS finding exists (SOAR / CI)")
    t.add_argument("--no-color", action="store_true")
    t.set_defaults(func=cmd_triage)

    r = sub.add_parser("rules", help="list detection rules")
    r.add_argument("--markdown", action="store_true")
    r.set_defaults(func=cmd_rules)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.func(args)
