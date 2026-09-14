"""Detection by content, directory walking and fail-closed behaviour."""
import os

import builders as b
import pytest

from modelwarden.core.detect import Format, detect
from modelwarden.core.engine import scan_paths
from modelwarden.core.findings import Severity
from modelwarden.core.registry import Registry


@pytest.mark.parametrize(
    ("name", "data", "expected"),
    [
        ("model.safetensors", b.global_call("os", "system"), Format.PICKLE),  # spoofed extension
        ("weights.txt", b.proto0_call("os", "system"), Format.PICKLE),
        ("config.json", b'{"key": {"nested": 1}}', Format.UNKNOWN),  # "{" at byte 8
        ("README.md", b"# hello\n", Format.UNKNOWN),
        ("empty.bin", b"", Format.UNKNOWN),
        ("model.gguf", b"GGUF\x03\x00\x00\x00", Format.GGUF),
    ],
)
def test_detection_ignores_extensions(tmp_path, name, data, expected):
    assert detect(b.write(tmp_path / name, data)) is expected


@pytest.mark.usefixtures("stub_policy")
def test_renamed_pickle_is_still_scanned(tmp_path):
    path = b.write(tmp_path / "model.safetensors", b.global_call("os", "system"))
    assert [f.rule.id for f in scan_paths([path]).findings] == ["MW-SC-001"]


def test_unknown_content_counts_as_skipped_or_unrecognised(tmp_path):
    b.write(tmp_path / "README.md", b"# docs\n")
    b.write(tmp_path / "weights.bin", b"\x00\x01garbage")
    result = scan_paths([tmp_path])
    assert result.skipped == 1
    assert [f.rule.id for f in result.findings] == ["MW-GEN-001"]


def test_recognised_format_without_a_scanner(tmp_path):
    path = b.write(tmp_path / "model.gguf", b"GGUF\x03\x00\x00\x00")
    [finding] = scan_paths([path], Registry([])).findings
    assert finding.rule.id == "MW-GEN-002"


def test_walk_skips_symlinks_and_fifos(tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    target = b.write(outside / "evil.pkl", b.global_call("os", "system"))
    scanned = tmp_path / "scanned"
    scanned.mkdir()
    (scanned / "link.pkl").symlink_to(target)
    os.mkfifo(scanned / "pipe.pkl")  # opening it would block forever
    result = scan_paths([scanned])
    assert (result.scanned, result.skipped, result.findings) == (0, 0, [])


def test_scanner_crash_fails_closed(tmp_path):
    class Exploding:
        name = "exploding"
        formats = frozenset({Format.PICKLE})
        rules = ()

        def scan(self, path, display):
            raise RuntimeError("boom")

    path = b.write(tmp_path / "model.pkl", b.plain_data())
    [finding] = scan_paths([path], Registry([Exploding()])).findings
    assert (finding.rule.id, finding.severity) == ("MW-GEN-004", Severity.HIGH)


def test_two_scanners_cannot_claim_one_format():
    class Claim:
        name = "claim"
        formats = frozenset({Format.PICKLE})
        rules = ()

    with pytest.raises(ValueError):
        Registry([Claim(), Claim()])


def _spread(tmp_path, count=6):
    """Enough files that a pool has something to spread; half of them not models."""
    for i in range(count):
        b.write(tmp_path / f"model{i}.pkl", b.global_call("os", "system"))
        b.write(tmp_path / f"notes{i}.txt", b"just prose\n")
    return tmp_path


@pytest.mark.usefixtures("stub_policy")
def test_jobs_reports_exactly_what_one_process_reports(tmp_path):
    """Parallel is only worth having if it is indistinguishable from sequential.

    Order included: `iter_files` sorts and `map` preserves input order, so two runs of
    the same tree must diff clean. A scanner that reordered under --jobs would make
    comparing two reports impossible.
    """
    _spread(tmp_path)
    one = scan_paths([tmp_path], jobs=1)
    many = scan_paths([tmp_path], jobs=4)

    def shape(result):
        return [(f.rule.id, f.location.path, f.evidence) for f in result.findings]

    assert shape(one) == shape(many)
    assert (one.scanned, one.skipped) == (many.scanned, many.skipped)


@pytest.mark.usefixtures("stub_policy")
def test_a_single_file_does_not_start_a_pool(tmp_path):
    # Starting processes costs more than scanning a small input, so --jobs on one file
    # stays sequential. Checked by result rather than by counting processes.
    path = b.write(tmp_path / "model.pkl", b.global_call("os", "system"))
    assert [f.rule.id for f in scan_paths([path], jobs=8).findings] == ["MW-SC-001"]


def test_the_allowlist_survives_the_process_boundary(tmp_path):
    """The one thing that could fail silently.

    `allowing()` is a context manager and cannot span a fork, so a worker adopts the
    allowlist at start-up instead. If that were dropped, an import the user explicitly
    allowed would come back as HIGH rather than INFO — a scan that quietly disagrees
    with its own flags.

    The pair matters: a known-dangerous global stays CRITICAL whatever the user allows
    (classify_global, and test_policy pins it), so `os:system` would pass this test even
    if the allowlist never crossed the fork. Only an unknown import can show the
    difference, which is why the run without the allowlist is asserted alongside.
    """
    for i in range(3):
        b.write(tmp_path / f"model{i}.pkl", b.global_call("mylib", "Thing"))

    def severities(**kwargs):
        findings = scan_paths([tmp_path], jobs=4, **kwargs).findings
        return {f.severity for f in findings if f.rule.id == "MW-SC-001"}

    assert severities() == {Severity.HIGH}
    assert severities(allowed=[("mylib", "Thing")]) == {Severity.INFO}


def test_missing_path_is_an_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        scan_paths([tmp_path / "nope"])


@pytest.mark.skipif(os.geteuid() == 0, reason="root can read a file with mode 000")
def test_an_unreadable_file_is_reported_not_skipped(tmp_path):
    """MW-GEN-003, found by an audit to be named in no test.

    A file the scanner cannot open is the plainest case of "nothing here was checked",
    and silence would be indistinguishable from a clean result. It is counted as
    scanned, because a file that was refused is not a file that was passed over.
    """
    path = b.write(tmp_path / "locked.pkl", b.global_call("os", "system"))
    path.chmod(0o000)
    try:
        result = scan_paths([path])
    finally:
        path.chmod(0o644)
    [finding] = result.findings
    assert (finding.rule.id, finding.severity) == ("MW-GEN-003", Severity.MEDIUM)
    assert (result.scanned, result.skipped) == (1, 0)
