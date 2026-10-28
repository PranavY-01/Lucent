"""Deduplication by (type, canonical value) with merged provenance (§B8.3)."""

from __future__ import annotations

from dataclasses import dataclass, field

from lucent_ioc.config import IOC_TYPE_ORDER, MAX_ORIGINAL_VALUES_PER_IOC
from lucent_ioc.models import IOCRecord, IOCType, SourceRef

_TYPE_RANK = {t: n for n, t in enumerate(IOC_TYPE_ORDER)}


@dataclass
class _Entry:
    occurrences: int = 0
    sources: dict[tuple, SourceRef] = field(default_factory=dict)
    original_values: set[str] = field(default_factory=set)


class Deduplicator:
    def __init__(self) -> None:
        self._entries: dict[tuple[IOCType, str], _Entry] = {}

    def add(self, ioc_type: IOCType, value: str, original_value: str, source: SourceRef) -> None:
        entry = self._entries.setdefault((ioc_type, value), _Entry())
        entry.occurrences += 1
        entry.sources.setdefault(source.identity(), source)
        entry.original_values.add(original_value)

    def records(self, max_sources_per_ioc: int) -> list[IOCRecord]:
        """Build sorted, capped IOC records."""
        out = []
        for (ioc_type, value), entry in self._entries.items():
            sources = sorted(entry.sources.values(), key=SourceRef.sort_key)
            originals = sorted(entry.original_values)
            out.append(
                IOCRecord(
                    type=ioc_type,
                    value=value,
                    occurrences=entry.occurrences,
                    source_count=len(sources),
                    sources_truncated=len(sources) > max_sources_per_ioc,
                    original_values=originals[:MAX_ORIGINAL_VALUES_PER_IOC],
                    original_values_truncated=len(originals) > MAX_ORIGINAL_VALUES_PER_IOC,
                    sources=sources[:max_sources_per_ioc],
                )
            )
        out.sort(key=lambda r: (_TYPE_RANK[r.type.value], r.value))
        return out
