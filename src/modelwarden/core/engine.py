"""Walks the given paths and hands each file to the scanner for its format."""
from __future__ import annotations

import os
from collections.abc import Iterable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from modelwarden.core.detect import Format, inspect
from modelwarden.core.findings import Finding, Location
from modelwarden.core.policy import allowing, pinning
from modelwarden.core.registry import Registry
from modelwarden.core.rules import (
    MULTIPLE_FORMATS,
    NOT_ANALYSED,
    READ_ERROR,
    SCANNER_ERROR,
    UNCLASSIFIED,
    UNRECOGNISED,
)

# Extensions that make an unrecognised file worth a finding. Anything else with
# unknown content (README, tokenizer.json, ...) is just counted as skipped.
MODEL_EXTENSIONS = frozenset({
    ".bin", ".ckpt", ".dill", ".gguf", ".h5", ".hdf5", ".joblib", ".keras", ".mar",
    ".model", ".npy", ".npz", ".onnx", ".pickle", ".pkl", ".pt", ".pth", ".safetensors",
})


@dataclass
class ScanResult:
    findings: list[Finding] = field(default_factory=list)
    scanned: int = 0
    skipped: int = 0


def iter_files(paths: Iterable[Path]) -> Iterator[Path]:
    for root in paths:
        if root.is_file():
            yield root
        elif root.is_dir():
            # followlinks=False: a symlink loop or a link to /etc is not a model.
            for dirpath, dirnames, filenames in os.walk(root):
                dirnames.sort()
                for name in sorted(filenames):
                    path = Path(dirpath, name)
                    # Opening a FIFO blocks forever; only regular files are scanned.
                    if not path.is_symlink() and path.is_file():
                        yield path
        else:
            raise FileNotFoundError(f"not a regular file or directory: {root}")


def display_path(path: Path) -> str:
    try:
        return path.resolve().relative_to(Path.cwd().resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def scan_paths(
    paths: Iterable[Path],
    registry: Registry | None = None,
    allowed: Iterable[tuple[str, str]] = (),
    lock: dict | None = None,
    jobs: int = 1,
) -> ScanResult:
    """Scan files and directories.

    `allowed` extends the import allowlist for this scan; `lock` pins MCP tool
    definitions so that changes since it was written are reported. `jobs` spreads the
    files over that many processes.

    Measured before being written: scanning is CPU-bound, 1.22s of processor time out
    of 1.23s wall for eight 90 MB models, with 60% of it inside the protobuf field
    walk. Threads would buy nothing against that; processes buy the core count. Small
    inputs stay sequential because starting a pool costs more than scanning them.
    """
    registry = registry or Registry.default()
    files = list(iter_files(paths))
    if jobs > 1 and len(files) > 1:
        return _scan_in_parallel(files, allowed, lock, jobs)

    result = ScanResult()
    with allowing(allowed), pinning(lock):
        for path in files:
            _absorb(result, _scan_file(path, registry))
    return result


def _absorb(result: ScanResult, outcome: tuple[list[Finding], int, int]) -> None:
    findings, scanned, skipped = outcome
    result.findings.extend(findings)
    result.scanned += scanned
    result.skipped += skipped


# One registry per worker process, built once. Passing it through would serialise the
# whole scanner set for every file.
_WORKER: Registry | None = None


def _start_worker(allowed: Iterable[tuple[str, str]], lock: dict | None) -> None:
    global _WORKER
    from modelwarden.core.policy import adopt

    adopt(allowed, lock)
    _WORKER = Registry.default()


def _scan_in_worker(path: Path) -> tuple[list[Finding], int, int]:
    return _scan_file(path, _WORKER or Registry.default())


def _scan_in_parallel(
    files: list[Path], allowed: Iterable[tuple[str, str]], lock: dict | None, jobs: int
) -> ScanResult:
    """Scan files across processes, in the order they were walked.

    `map` preserves input order and `iter_files` already sorts, so a parallel run
    reports findings in exactly the sequence a sequential one does. A scanner that
    reordered its output under `--jobs` would make two runs impossible to diff.
    """
    from concurrent.futures import ProcessPoolExecutor

    result = ScanResult()
    with ProcessPoolExecutor(
        max_workers=jobs, initializer=_start_worker, initargs=(tuple(allowed), lock)
    ) as pool:
        for outcome in pool.map(_scan_in_worker, files):
            _absorb(result, outcome)
    return result


def _scan_file(path: Path, registry: Registry) -> tuple[list[Finding], int, int]:
    """Findings for one file, with how it counted: (findings, scanned, skipped).

    Counts are returned rather than added to a shared result, because in a worker
    process there is no shared result to add them to.
    """
    display = display_path(path)
    here = Location(display)
    try:
        detection = inspect(path)
    except OSError as exc:
        return [Finding(READ_ERROR, READ_ERROR.default_severity, str(exc), here)], 1, 0

    formats = detection.formats
    if not formats:
        # Before the extension test, and regardless of it: a limit that stopped the
        # search is a gap in the scan, not evidence about what the file is. The
        # extension rule below exists to keep READMEs quiet, and it was silencing
        # this too — a poisoned MCP tool list padded past the limit reported nothing.
        if detection.undecided:
            msg = "not classified, so nothing in it was checked: " + "; ".join(
                detection.undecided)
            return [Finding(UNCLASSIFIED, UNCLASSIFIED.default_severity, msg, here)], 1, 0
        if path.suffix.lower() not in MODEL_EXTENSIONS:
            return [], 0, 1
        msg = f"content of this {path.suffix} file matches no supported format"
        return [Finding(UNRECOGNISED, UNRECOGNISED.default_severity, msg, here)], 1, 0

    findings: list[Finding] = []
    if len(formats) > 1:
        names = ", ".join(fmt.value for fmt in formats)
        findings.append(Finding(
            MULTIPLE_FORMATS, MULTIPLE_FORMATS.default_severity,
            f"the bytes satisfy {len(formats)} formats at once: {names}", here, names))

    # Every matching format is scanned, not just the first: guessing once and guessing
    # wrong means reporting on a file nobody will load.
    for fmt in formats:
        findings.extend(_scan_as(path, display, here, fmt, registry))
    return findings, 1, 0


def _scan_as(
    path: Path, display: str, here: Location, fmt: Format, registry: Registry
) -> list[Finding]:
    scanner = registry.for_format(fmt)
    if scanner is None:
        msg = f"{fmt.value} file recognised, no scanner for this format yet"
        return [Finding(NOT_ANALYSED, NOT_ANALYSED.default_severity, msg, here)]
    # Collect eagerly: scanners are generators, so errors surface while iterating.
    try:
        return list(scanner.scan(path, display))
    except OSError as exc:
        return [Finding(READ_ERROR, READ_ERROR.default_severity, str(exc), here)]
    except Exception as exc:  # noqa: BLE001 — fail closed on any scanner bug
        msg = f"{scanner.name} scanner failed: {type(exc).__name__}: {exc}"
        return [Finding(SCANNER_ERROR, SCANNER_ERROR.default_severity, msg, here)]
