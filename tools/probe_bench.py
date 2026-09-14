"""Per-attempt measurement harness, for deciding whether a technique earns its place.

`probe_target` reports a rate per probe, which answers "is this endpoint weak" but not
"did the technique I just added do anything". This runs every attempt separately and
reports hits per label, so one iteration can be compared with the one before it.

Not part of the package: an instrument that lives beside the work, like the lexical
retriever. Nothing here is imported by a scanner.

    python tools/probe_bench.py URL MODEL [SAMPLES] [OUT.json]

Writes JSON so two runs can be diffed, and prints what moved since the previous one.
"""
from __future__ import annotations

import json
import sys
import time
from pathlib import Path

# Run from a checkout without installing: src/ sits next to this file's parent.
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from modelwarden.scanners.llm.probes import BUILTIN_PROBES, new_canary  # noqa: E402
from modelwarden.scanners.llm.target import ChatTarget, TargetError  # noqa: E402


def measure(target: ChatTarget, samples: int) -> dict:
    """Hits per attempt label, for every probe."""
    started = time.monotonic()
    out: dict = {"model": target.model, "samples": samples, "probes": {}}
    calls = 0

    for probe in BUILTIN_PROBES:
        per_label: dict[str, dict] = {}
        # Labels come from one throwaway build; each sample then rebuilds the attempt
        # around its own canary. A fresh canary per sample, not per probe: measured,
        # `format_task` scores 5/5 when one canary is repeated five times and 6/10
        # across ten different ones, `summarise` 5/5 against 4/10. At temperature 0 the
        # canary is the only thing that varies, so repeating one measures a single case
        # five times rather than the technique five times — and two runs that drew
        # different canaries were two different instruments.
        for label in [a.label for a in probe.build(new_canary())]:
            hits = 0
            done = 0
            error: str | None = None
            for _ in range(samples):
                canary = new_canary()
                attempt = next(a for a in probe.build(canary) if a.label == label)
                try:
                    if attempt.follow_ups:
                        replies = target.converse(
                            [attempt.user, *attempt.follow_ups], attempt.system)
                        calls += 1 + len(attempt.follow_ups)
                    else:
                        replies = [target.ask(attempt.user, attempt.system)]
                        calls += 1
                except TargetError as exc:
                    error = str(exc)
                    print(f"  !! {probe.name}/{label}: {exc}", file=sys.stderr)
                    break
                done += 1
                if any(probe.detect(reply, canary) for reply in replies):
                    hits += 1

            # `samples` is what was actually measured, not what was asked for. The old
            # version recorded the requested count whatever happened, so an attempt that
            # lost the endpoint on its first sample was stored as 0/5 -- byte for byte
            # what five measured refusals look like. That is MW-LLM-009's own principle,
            # broken by the instrument that reports it: an endpoint that could not be
            # probed is not an endpoint that passed. It cost a whole run to notice, when
            # the server died part way and eight attempts came back as confident zeros.
            per_label[label] = {"hits": hits, "samples": done}
            if error is not None:
                per_label[label]["error"] = error
                per_label[label]["asked_for"] = samples
            mark = "#" * hits + "." * (done - hits)
            # flush=True: redirected to a file, Python switches to block buffering and a
            # long run looks dead for minutes while working. Progress nobody can see is
            # not progress reporting.
            if done == 0:
                shown = "-" * samples + "  NOT MEASURED (endpoint failed)"
            elif error is not None:
                shown = f"{mark} {hits}/{done}  incomplete: {samples - done} never ran"
            else:
                shown = f"{mark} {hits}/{done}"
            print(f"  {probe.name:22} {label:18} {shown}", flush=True)

        total = sum(v["hits"] for v in per_label.values())
        possible = sum(v["samples"] for v in per_label.values())
        failed = sorted(k for k, v in per_label.items() if "error" in v)
        out["probes"][probe.name] = {
            "rule": probe.rule.id,
            "attempts": per_label,
            "hits": total,
            "possible": possible,
        }
        if failed:
            out["probes"][probe.name]["failed"] = failed
        note = f"   ({len(failed)} attempt(s) not measured)" if failed else ""
        print(f"  {'':22} {'TOTAL':18} {total}/{possible}{note}\n", flush=True)

    out["calls"] = calls
    out["seconds"] = round(time.monotonic() - started, 1)
    out["hits"] = sum(p["hits"] for p in out["probes"].values())
    out["possible"] = sum(p["possible"] for p in out["probes"].values())
    return out


def compare(old: dict, new: dict) -> None:
    """What moved between two runs, per label. The point of the exercise."""
    print("\n=== change since the previous run ===")
    for name, probe in new["probes"].items():
        before = old.get("probes", {}).get(name, {}).get("attempts", {})
        for label, entry in probe["attempts"].items():
            was = before.get(label)
            if was is None:
                print(f"  NEW    {name}/{label}: {entry['hits']}/{entry['samples']}")
            elif "error" in entry or "error" in was:
                # Never a movement: one side of this comparison is not a measurement.
                print(f"  UNMEASURED {name}/{label}: an endpoint failure on one side")
            elif was["hits"] != entry["hits"]:
                print(f"  MOVED  {name}/{label}: {was['hits']} -> {entry['hits']}")
    print(f"  overall: {old.get('hits', '?')}/{old.get('possible', '?')} "
          f"-> {new['hits']}/{new['possible']}")


def main(argv: list[str]) -> int:
    if len(argv) < 3:
        print(__doc__)
        return 2
    url, model = argv[1], argv[2]
    samples = int(argv[3]) if len(argv) > 3 else 3
    out_path = Path(argv[4]) if len(argv) > 4 else Path("probe_bench.json")

    # Read the previous run before measuring, so the output file is free to be used as
    # a completion signal. Priming it by copying the last run in — the obvious way to
    # get a comparison — made "the file exists" mean "finished" from the first second,
    # and a watcher believed a run had ended four seconds after it started.
    previous: dict | None = None
    if out_path.exists():
        try:
            previous = json.loads(out_path.read_text())
        except ValueError:
            previous = None
        out_path.unlink()

    target = ChatTarget(url=url, model=model, timeout=300.0)
    print(f"=== {model} at {url}, {samples} sample(s) per attempt ===\n", flush=True)
    result = measure(target, samples)

    if previous is not None:
        compare(previous, result)
    out_path.write_text(json.dumps(result, indent=2) + "\n")

    print(f"\n=== {result['hits']}/{result['possible']} attempts hit, "
          f"{result['calls']} calls in {result['seconds']}s -> {out_path} ===")

    # A run that lost its endpoint is not a low score, it is not a score. Saying so in
    # the exit code as well as the text keeps a wrapper or a watcher from reading the
    # totals of a half-dead run as a result.
    failed = sum(len(p.get("failed", ())) for p in result["probes"].values())
    if failed:
        print(f"=== {failed} attempt(s) NOT MEASURED: the endpoint failed part way. "
              "Totals above cover only what was actually asked. ===")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
