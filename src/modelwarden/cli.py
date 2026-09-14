"""Command-line entry point: `modelwarden scan`, `rules`, `lock` and `probe`."""
from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from modelwarden import __version__
from modelwarden.core.engine import ScanResult, scan_paths
from modelwarden.core.findings import Severity
from modelwarden.core.policy import parse_allow_entry, read_allow_file, read_lock_file
from modelwarden.core.registry import Registry
from modelwarden.reporters import REPORTERS
from modelwarden.scanners.agents.live import DEFAULT_TIMEOUT as LIVE_TIMEOUT
from modelwarden.scanners.llm.probes import DEFAULT_SAMPLES as PROBE_SAMPLES

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_USAGE = 2  # also what argparse uses for bad arguments


def _add_baseline_arguments(parser: argparse.ArgumentParser) -> None:
    """The first scan of an existing project is a wall of findings, and a wall is what
    gets a scanner switched off — not because the findings are wrong, but because nobody
    can tell which one is new today. A baseline records what was accepted; later runs
    report the difference and always say how many were held back.
    """
    parser.add_argument(
        "--baseline", type=Path, metavar="FILE",
        help="suppress findings recorded in this file, and report how many were held back",
    )
    parser.add_argument(
        "--save-baseline", type=Path, metavar="FILE",
        help="write the findings of this run to FILE as the accepted baseline",
    )


def _threshold(value: str) -> Severity | None:
    if value.strip().lower() == "none":
        return None
    try:
        return Severity.parse(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def _allow_entry(value: str) -> tuple[str, str]:
    try:
        return parse_allow_entry(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from None


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="modelwarden", description="Security validation for AI models."
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="scan model files and directories")
    scan.add_argument("paths", nargs="+", type=Path)
    scan.add_argument("-f", "--format", choices=sorted(REPORTERS), default="console")
    scan.add_argument("-o", "--output", type=Path, help="write the report to a file")
    scan.add_argument(
        "--fail-on",
        type=_threshold,
        default=Severity.HIGH,
        metavar="SEVERITY",
        help="exit 1 when a finding is at or above this severity "
        "(default: high; 'none' never fails)",
    )

    scan.add_argument(
        "--allow",
        action="append",
        default=[],
        type=_allow_entry,
        metavar="MODULE:NAME",
        help="treat an import as expected: reported as info instead of high "
        "(repeatable; known-dangerous imports stay critical)",
    )
    scan.add_argument(
        "--allow-file",
        type=Path,
        metavar="FILE",
        help="file with one MODULE:NAME per line, '#' starts a comment",
    )

    scan.add_argument(
        "--lock",
        type=Path,
        metavar="FILE",
        help="lockfile of pinned MCP tool definitions; report anything that changed since it",
    )

    scan.add_argument(
        "--jobs", type=int, default=1, metavar="N",
        help="scan files across N processes (default 1; scanning is CPU-bound, so this "
             "scales with cores on large models)",
    )

    _add_baseline_arguments(scan)

    sub.add_parser("rules", help="list detection rules")

    lock = sub.add_parser("lock", help="pin MCP tool definitions to a lockfile")
    lock.add_argument("path", type=Path, help="a tools/list result to pin")
    lock.add_argument("-o", "--output", type=Path, help="write here instead of standard output")

    probe = sub.add_parser("probe", help="send probes to a live LLM endpoint")
    probe.add_argument("url", help="base URL of an OpenAI-compatible endpoint")
    probe.add_argument("-m", "--model", required=True, help="model name to ask for")
    probe.add_argument("-n", "--samples", type=int, default=PROBE_SAMPLES,
                       help=f"repeats per prompt (default: {PROBE_SAMPLES})")
    probe.add_argument("--api-key-env", metavar="VAR",
                       help="environment variable holding the API key; the key is never "
                            "taken from the command line, where it would reach shell "
                            "history and the process list")
    probe.add_argument("--timeout", type=float, default=120.0, metavar="SECONDS")
    probe.add_argument("--probe-file", type=Path, metavar="FILE",
                       help="JSON probe definitions to run instead of the built-in ones")
    probe.add_argument("-f", "--format", choices=sorted(REPORTERS), default="console")
    probe.add_argument("-o", "--output", type=Path, help="write the report to a file")
    probe.add_argument("--fail-on", type=_threshold, default=Severity.HIGH, metavar="SEVERITY",
                       help="exit 1 when a finding is at or above this severity (default: high)")

    # The command is named here, never taken from a configuration file: questioning a
    # server means running it, so the decision to run it stays with the user.
    live = sub.add_parser("server", help="question a live MCP server and judge its tools")
    # Deliberately not named "command": add_subparsers already uses that dest for the
    # subcommand itself, and a positional of the same name overwrites it in silence —
    # the branch below then never runs and the parse looks fine.
    live.add_argument("argv", nargs="*", metavar="COMMAND",
                      help="the server's command and arguments, for a stdio server")
    live.add_argument("--url", help="HTTP endpoint of the server, instead of starting one")
    live.add_argument("--header", action="append", default=[], metavar="NAME:VALUE",
                      help="extra HTTP header (repeatable); no flag takes a bare token")
    live.add_argument("--timeout", type=float, default=LIVE_TIMEOUT, metavar="SECONDS")
    live.add_argument("--lock", type=Path, metavar="FILE",
                      help="compare what the server offers against a lockfile")
    live.add_argument("--save-lock", type=Path, metavar="FILE",
                      help="write a lockfile from what the server offers right now")
    live.add_argument("-f", "--format", choices=sorted(REPORTERS), default="console")
    live.add_argument("-o", "--output", type=Path, help="write the report to a file")
    live.add_argument("--fail-on", type=_threshold, default=Severity.HIGH, metavar="SEVERITY",
                      help="exit 1 when a finding is at or above this severity (default: high)")

    # Opt-in rather than detected by content: a corpus document is an ordinary text
    # file, and so is every README next to it. Only the user knows what gets indexed.
    corpus = sub.add_parser("corpus", help="scan documents on their way into a RAG index")
    corpus.add_argument("paths", nargs="+", type=Path)
    _add_baseline_arguments(corpus)
    corpus.add_argument("-f", "--format", choices=sorted(REPORTERS), default="console")
    corpus.add_argument("-o", "--output", type=Path, help="write the report to a file")
    corpus.add_argument("--fail-on", type=_threshold, default=Severity.HIGH, metavar="SEVERITY",
                        help="exit 1 when a finding is at or above this severity "
                             "(default: high; 'none' never fails)")
    return parser


def _probe(args: argparse.Namespace) -> ScanResult:
    from modelwarden.scanners.llm.probes import BUILTIN_PROBES, load_probes, probe_target
    from modelwarden.scanners.llm.target import ChatTarget

    probes = load_probes(args.probe_file) if args.probe_file else BUILTIN_PROBES
    key = None
    if args.api_key_env:
        key = os.environ.get(args.api_key_env)
        if not key:
            raise ValueError(f"environment variable {args.api_key_env} is not set")
    target = ChatTarget(url=args.url, model=args.model, api_key=key, timeout=args.timeout)
    result = ScanResult(scanned=1)
    result.findings.extend(probe_target(target, probes, samples=args.samples))
    return result


def _live(args: argparse.Namespace) -> ScanResult:
    from modelwarden.core.policy import pinning
    from modelwarden.scanners.agents.live import HttpServer, StdioServer, scan_server

    if bool(args.url) == bool(args.argv):
        raise ValueError("name either a server command or --url, not both and not neither")
    if args.url:
        headers = {}
        for item in args.header:
            name, sep, value = item.partition(":")
            if not sep or not name.strip():
                raise ValueError(f"expected NAME:VALUE, got {item!r}")
            headers[name.strip()] = value.strip()
        server = HttpServer(url=args.url, headers=headers, timeout=args.timeout)
    else:
        server = StdioServer(command=args.argv[0], args=args.argv[1:],
                             timeout=args.timeout)

    lock = read_lock_file(args.lock) if args.lock else None
    result = ScanResult(scanned=1)
    with pinning(lock):
        result.findings.extend(scan_server(server, args.save_lock))
    return result


def _corpus(args: argparse.Namespace) -> ScanResult:
    from modelwarden.core.engine import display_path, iter_files
    from modelwarden.scanners.rag.corpus import scan_file

    result = ScanResult()
    for path in iter_files(args.paths):
        result.scanned += 1
        result.findings.extend(scan_file(path, display_path(path)))
    return result


def _write_lock(path: Path, output: Path | None) -> int:
    from modelwarden.scanners.agents.mcp import build_lock, extract_tools

    tools = extract_tools(json.loads(path.read_text(encoding="utf-8")))
    if not tools:
        print(f"modelwarden: {path}: no tool list in this document", file=sys.stderr)
        return EXIT_USAGE
    document = json.dumps(build_lock(tools), indent=2, sort_keys=True) + "\n"
    if output is None:
        sys.stdout.write(document)
    else:
        output.write_text(document, encoding="utf-8")
        print(f"pinned {len(tools)} tool(s) to {output}")
    return EXIT_OK


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    registry = Registry.default()

    if args.command == "rules":
        for rule in registry.rules:
            tags = ", ".join((*rule.atlas, *rule.owasp))
            print(f"{rule.id:<10} {str(rule.default_severity):<8} {rule.title}  [{tags}]")
        return EXIT_OK

    try:
        if args.command == "lock":
            return _write_lock(args.path, args.output)
        if args.command == "probe":
            result = _probe(args)
            return _report(result, registry, args)
        if args.command == "corpus":
            return _report(_corpus(args), registry, args)
        if args.command == "server":
            return _report(_live(args), registry, args)
        allowed = set(args.allow)
        if args.allow_file:
            allowed |= read_allow_file(args.allow_file)
        lock = read_lock_file(args.lock) if args.lock else None
        if args.jobs < 1:
            raise ValueError(f"--jobs must be at least 1, got {args.jobs}")
        result = scan_paths(args.paths, registry, allowed, lock, jobs=args.jobs)
        # Inside the try as well: reporting reads user-supplied files too (a baseline),
        # and a malformed one has to be the usage error a malformed lockfile already is.
        # This return used to sit outside, so a broken baseline gave `scan` a traceback
        # while `corpus` handled it — the same input, two behaviours.
        return _report(result, registry, args)
    except (OSError, ValueError) as exc:
        print(f"modelwarden: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _apply_baseline(result: ScanResult, args: argparse.Namespace) -> None:
    """Suppress what was accepted before, and say so. Never silently.

    Saving happens before suppressing, so `--save-baseline` records the run as it
    actually was rather than what survived a filter.
    """
    from modelwarden.core import baseline

    save_to = getattr(args, "save_baseline", None)
    if save_to is not None:
        written = baseline.save(save_to, result.findings)
        print(f"modelwarden: wrote {written} finding(s) to {save_to}", file=sys.stderr)

    known_from = getattr(args, "baseline", None)
    if known_from is None:
        return
    kept, suppressed = baseline.apply(result.findings, baseline.load(known_from))
    result.findings[:] = kept
    # Reported even when zero: a baseline that suppresses nothing usually means the
    # paths moved, and silence would look like a clean run.
    print(f"modelwarden: baseline suppressed {suppressed} finding(s)", file=sys.stderr)


def _report(result: ScanResult, registry: Registry, args: argparse.Namespace) -> int:
    _apply_baseline(result, args)
    render = REPORTERS[args.format]
    if args.output:
        with args.output.open("w", encoding="utf-8") as out:
            render(result, registry.rules, out)
    else:
        render(result, registry.rules, sys.stdout)

    if args.fail_on is not None and any(f.severity >= args.fail_on for f in result.findings):
        return EXIT_FINDINGS
    return EXIT_OK
