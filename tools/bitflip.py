"""Single-bit sweep: which flips leave a file parsed, its evidence intact, and the scan silent.

A structure that declares how much there is to walk is believed, and a
smaller-but-plausible number produces a shorter, valid, silent traversal. Fail-closed
never fires because nothing looks broken. That is the defect class this measures, and
it is the one that produced the two narrow HDF5 checks in 0.2.1 and the ONNX
orphan-opset check later — each of which was calibrated against numbers from a sweep
like this one rather than against an idea about where the gap was.

The instrument lived outside the repository until now, which meant the figure everyone
quotes (198 flips over ten fixtures, on 0.2.0) could not be reproduced or moved. A
measurement nobody can repeat is an anecdote.

**What a hit here is, and is not.** A flip counted below leaves the file classified as
its format, leaves the evidence bytes where they were, and produces no finding at all.
That is a *candidate*, not a confirmed defect, and the gap is real: the same flip may
have made the payload inert rather than invisible. Breaking the `"mcpServers"` key of a
client configuration hides its servers from this scanner, and from the client that
would have launched them — nothing was silenced that still mattered. Only reading the
mechanism separates the two, which is how the two HDF5 checks in 0.2.1 were calibrated
and why they are as narrow as they are.

So the number is a **regression signal, not a defect count**. Its value is the
difference between two runs: a change that makes the scanner quieter shows up here
before anybody notices it in the field.

Not part of the package: an instrument that lives beside the work, like probe_bench.
Nothing here is imported by a scanner.

    python tools/bitflip.py [FIXTURES_DIR] [OUT.json] [MAX_BYTES]

Writes JSON so two runs can be diffed, and prints what moved since the previous one.
MAX_BYTES caps which fixtures are swept; whatever is skipped is named in the output
rather than quietly dropped, because a coverage number nobody states reads as "all".
"""
from __future__ import annotations

import json
import sys
import tempfile
import time
from pathlib import Path

# Run from a checkout without installing: src/ sits next to this file's parent.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from modelwarden.core.detect import detect_all  # noqa: E402
from modelwarden.core.engine import scan_paths  # noqa: E402

DEFAULT_MAX_BYTES = 4096


def flip(data: bytes, offset: int, bit: int) -> bytes:
    out = bytearray(data)
    out[offset] ^= 1 << bit
    return bytes(out)


def needles(findings, data: bytes) -> list[bytes]:
    """The payload bytes a finding is about, as they appear in the file.

    A flip that destroys the payload is not a silencing: there is nothing left to
    report. So every sweep has to be able to tell "the scanner stopped seeing it" from
    "it stopped being there", and the only honest way is to look for it in the bytes.

    Evidence is not always literal. MW-SC-060 reads `file:path`, a string the scanner
    composed out of two fields and which appears nowhere in the file, so the longest
    component that *is* present stands in for it. A finding with no evidence at all
    contributes no needle, and that fixture is then judged on "still a format, still
    silent" alone — weaker, and stated as such in the output.
    """
    found: list[bytes] = []
    for finding in findings:
        if not finding.evidence:
            continue
        whole = finding.evidence.encode("utf-8", "replace")
        if whole in data:
            found.append(whole)
            continue
        parts = [p for p in whole.replace(b"!", b":").split(b":") if len(p) > 3 and p in data]
        if parts:
            found.append(max(parts, key=len))
    return found


def sweep(path: Path, work: Path) -> dict:
    """Every single-bit flip of one fixture, classified."""
    data = path.read_bytes()
    baseline = scan_paths([path]).findings
    marks = needles(baseline, data)
    mutant = work / path.name

    counts = {"silent": 0, "reported": 0, "undetected": 0, "evidence_destroyed": 0}
    silenced: list[list[int]] = []
    for offset in range(len(data)):
        for bit in range(8):
            candidate = flip(data, offset, bit)
            if any(mark not in candidate for mark in marks):
                counts["evidence_destroyed"] += 1
                continue
            mutant.write_bytes(candidate)
            if scan_paths([mutant]).findings:
                counts["reported"] += 1
            elif not detect_all(mutant):
                # Not this format any more, so nothing claims to have checked it.
                counts["undetected"] += 1
            else:
                counts["silent"] += 1
                silenced.append([offset, bit])

    return {
        "bytes": len(data),
        "flips": len(data) * 8,
        "baseline_rules": sorted({f.rule.id for f in baseline}),
        "needles": [m.decode("utf-8", "replace") for m in marks],
        "counts": counts,
        # Fixtures whose findings carry no evidence bytes cannot answer "is the payload
        # still there", so their hits are weaker and kept out of the headline total.
        "verifiable": bool(marks),
        "silent": silenced,
    }


def finding_bearing(root: Path, max_bytes: int) -> tuple[list[Path], list[tuple[Path, int]]]:
    """Fixtures worth sweeping, and the ones left out for being too large to afford."""
    chosen, skipped = [], []
    for path in sorted(root.rglob("*")):
        if not path.is_file() or path.suffix in {".py", ".md"}:
            continue
        if not scan_paths([path]).findings:
            continue  # nothing to silence
        size = path.stat().st_size
        if size <= max_bytes:
            chosen.append(path)
        else:
            skipped.append((path, size))
    return chosen, skipped


def measure(root: Path, max_bytes: int) -> dict:
    started = time.monotonic()
    chosen, skipped = finding_bearing(root, max_bytes)
    out: dict = {"max_bytes": max_bytes, "fixtures": {}, "skipped": {}}
    for path, size in skipped:
        out["skipped"][str(path.relative_to(root))] = size
    if skipped:
        print(f"!! {len(skipped)} finding-bearing fixture(s) over {max_bytes} bytes are NOT "
              f"swept: {', '.join(str(p.relative_to(root)) for p, _ in skipped)}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp)
        for path in chosen:
            name = str(path.relative_to(root))
            result = sweep(path, work)
            out["fixtures"][name] = result
            weak = "" if result["verifiable"] else "   (no evidence bytes: not counted)"
            # flush: redirected to a file this buffers, and a long run looks dead.
            print(f"  {name:<34} {result['counts']['silent']:>4} silent of "
                  f"{result['flips']:>6} flips{weak}", flush=True)

    verifiable = [f for f in out["fixtures"].values() if f["verifiable"]]
    out["silent"] = sum(f["counts"]["silent"] for f in verifiable)
    out["silent_unverifiable"] = sum(
        f["counts"]["silent"] for f in out["fixtures"].values() if not f["verifiable"])
    out["flips"] = sum(f["flips"] for f in verifiable)
    out["swept"] = len(out["fixtures"])
    out["seconds"] = round(time.monotonic() - started, 1)
    return out


def compare(old: dict, new: dict) -> None:
    """What moved between two runs, per fixture. The point of the exercise."""
    print("\n=== change since the previous run ===")
    before = old.get("fixtures", {})
    for name, entry in new["fixtures"].items():
        was = before.get(name)
        now = entry["counts"]["silent"]
        if was is None:
            print(f"  NEW    {name}: {now} silent")
        elif was["counts"]["silent"] != now:
            print(f"  MOVED  {name}: {was['counts']['silent']} -> {now}")
    for name in before.keys() - new["fixtures"].keys():
        print(f"  GONE   {name}: was {before[name]['counts']['silent']} silent")
    print(f"  overall: {old.get('silent', '?')} -> {new['silent']} silent flips")


def main(argv: list[str]) -> int:
    here = Path(__file__).resolve().parents[1]
    root = Path(argv[1]) if len(argv) > 1 else here / "tests" / "fixtures"
    out_path = Path(argv[2]) if len(argv) > 2 else Path("bitflip.json")
    max_bytes = int(argv[3]) if len(argv) > 3 else DEFAULT_MAX_BYTES
    if not root.is_dir():
        print(__doc__)
        return 2

    # Read the previous run before measuring, so the output file stays usable as a
    # completion signal rather than existing from the first second.
    previous: dict | None = None
    if out_path.exists():
        try:
            previous = json.loads(out_path.read_text())
        except ValueError:
            previous = None
        out_path.unlink()

    print(f"=== single-bit sweep of {root}, fixtures up to {max_bytes} bytes ===\n", flush=True)
    result = measure(root, max_bytes)
    if previous is not None:
        compare(previous, result)
    out_path.write_text(json.dumps(result, indent=2) + "\n")

    print(f"\n=== {result['silent']} silent of {result['flips']} flips across "
          f"{result['swept']} fixtures in {result['seconds']}s -> {out_path} ===")
    print("=== a hit is a candidate, not a defect: the flip may have made the payload "
          "inert rather than invisible. Compare runs; read mechanisms. ===")
    if result["silent_unverifiable"]:
        print(f"=== {result['silent_unverifiable']} further silent flip(s) in fixtures whose "
              "findings carry no evidence bytes, excluded from the total above. ===")
    if result["skipped"]:
        print(f"=== {len(result['skipped'])} fixture(s) NOT swept, over the size cap. "
              "The totals above do not cover them. ===")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
