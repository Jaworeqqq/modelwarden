"""Scanner registry: which scanner handles which format, and the full rule catalogue."""
from __future__ import annotations

from collections.abc import Iterable
from pathlib import Path
from typing import Protocol

from modelwarden.core.detect import Format
from modelwarden.core.findings import Finding, Rule
from modelwarden.core.rules import ENGINE_RULES


class Scanner(Protocol):
    name: str
    formats: frozenset[Format]
    rules: tuple[Rule, ...]

    def scan(self, path: Path, display: str) -> Iterable[Finding]: ...


def builtin_scanners() -> list[Scanner]:
    from modelwarden.scanners.agents import mcp, mcp_config
    from modelwarden.scanners.supply_chain import (
        archive,
        gguf,
        hdf5,
        npy,
        onnx,
        pickle,
        safetensors,
    )

    return [
        mcp.MCPToolsScanner(),
        mcp_config.MCPConfigScanner(),
        pickle.PickleScanner(),
        archive.ZipScanner(),
        npy.NumpyScanner(),
        safetensors.SafetensorsScanner(),
        gguf.GGUFScanner(),
        hdf5.HDF5Scanner(),
        onnx.ONNXScanner(),
    ]


class Registry:
    def __init__(self, scanners: Iterable[Scanner]):
        self.scanners = list(scanners)
        self._by_format: dict[Format, Scanner] = {}
        for scanner in self.scanners:
            for fmt in scanner.formats:
                # One owner per format: two scanners silently shadowing each other
                # would make coverage depend on registration order.
                if fmt in self._by_format:
                    owner = self._by_format[fmt].name
                    raise ValueError(f"format {fmt.value!r} claimed by {owner} and {scanner.name}")
                self._by_format[fmt] = scanner

    @classmethod
    def default(cls) -> Registry:
        return cls(builtin_scanners())

    def for_format(self, fmt: Format) -> Scanner | None:
        return self._by_format.get(fmt)

    @property
    def rules(self) -> list[Rule]:
        # Probes and the corpus scanner are not format scanners: they have no format and
        # are not reached by detection, but their rules belong in the same catalogue, so
        # `modelwarden rules` lists everything the tool can report.
        from modelwarden.scanners.agents.live import LIVE_RULES
        from modelwarden.scanners.llm.probes import LLM_RULES
        from modelwarden.scanners.rag.corpus import RAG_RULES

        seen: dict[str, Rule] = {
            rule.id: rule for rule in (*ENGINE_RULES, *LLM_RULES, *RAG_RULES, *LIVE_RULES)
        }
        for scanner in self.scanners:
            for rule in scanner.rules:
                seen.setdefault(rule.id, rule)
        return list(seen.values())
