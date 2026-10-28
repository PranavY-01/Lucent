from lucent_ioc.deduplicator import Deduplicator
from lucent_ioc.models import IOCType, SourceRef
from lucent_ioc.pipeline import process_segment


def _dedup_lines(lines: list[str]) -> list:
    d = Deduplicator()
    for n, text in enumerate(lines, start=1):
        sightings, _ = process_segment(text, SourceRef(file="f.txt", line=n))
        for s in sightings:
            d.add(s.type, s.value, s.original_value, s.source)
    return d.records(100)


# §B15.2 deduplication golden rows


def test_repeat_on_two_lines():
    (rec,) = _dedup_lines(["203.0.113.10", "nothing here", "203.0.113.10"])
    assert (rec.occurrences, rec.source_count) == (2, 2)
    assert [s.line for s in rec.sources] == [1, 3]


def test_repeat_on_one_line():
    (rec,) = _dedup_lines(["203.0.113.10 203.0.113.10"])
    assert (rec.occurrences, rec.source_count, len(rec.sources)) == (2, 1, 1)


def test_case_and_defang_folding():
    (rec,) = _dedup_lines(["example.com", "EXAMPLE[.]com"])
    assert rec.type is IOCType.domain
    assert rec.original_values == ["EXAMPLE[.]com", "example.com"]


def test_url_host_merges_with_bare_domain():
    recs = _dedup_lines(["https://example.com/", "example.com"])
    assert [(r.type.value, r.value) for r in recs] == [
        ("domain", "example.com"),
        ("url", "https://example.com/"),
    ]
    domain = recs[0]
    assert domain.source_count == 2
    assert [s.model_dump(exclude_none=True) for s in domain.sources] == [
        {"file": "f.txt", "line": 1, "via": "url_host"},
        {"file": "f.txt", "line": 2},
    ]


# Unit behaviour


def test_via_is_part_of_source_identity():
    d = Deduplicator()
    d.add(IOCType.domain, "example.com", "example.com", SourceRef(file="a", line=1))
    d.add(IOCType.domain, "example.com", "example.com", SourceRef(file="a", line=1, via="url_host"))
    (rec,) = d.records(100)
    assert rec.source_count == 2


def test_never_merge_across_types():
    d = Deduplicator()
    src = SourceRef(file="a", line=1)
    d.add(IOCType.md5, "d41d8cd98f00b204e9800998ecf8427e", "x", src)
    d.add(IOCType.domain, "d41d8cd98f00b204e9800998ecf8427e", "x", src)
    assert len(d.records(100)) == 2


def test_source_cap_and_flag():
    d = Deduplicator()
    for line in range(10, 0, -1):
        d.add(IOCType.ipv4, "192.0.2.1", "192.0.2.1", SourceRef(file="a", line=line))
    (rec,) = d.records(3)
    assert rec.occurrences == 10
    assert rec.source_count == 10
    assert rec.sources_truncated is True
    assert [s.line for s in rec.sources] == [1, 2, 3]
    (rec,) = d.records(10)
    assert rec.sources_truncated is False


def test_original_values_cap_and_flag():
    d = Deduplicator()
    for i in range(25):
        d.add(IOCType.domain, "example.com", f"raw-{i:02d}", SourceRef(file="a", line=1))
    (rec,) = d.records(100)
    assert len(rec.original_values) == 20
    assert rec.original_values == sorted(rec.original_values)
    assert rec.original_values[0] == "raw-00"
    assert rec.original_values_truncated is True


def test_source_ordering_mixed_kinds():
    d = Deduplicator()
    for src in [
        SourceRef(file="b.json", path="$.z"),
        SourceRef(file="a.csv", record=2, column="x"),
        SourceRef(file="a.csv", record=1, column="y"),
        SourceRef(file="b.json", path="$.a"),
    ]:
        d.add(IOCType.domain, "example.com", "example.com", src)
    (rec,) = d.records(100)
    assert [(s.file, s.record, s.path) for s in rec.sources] == [
        ("a.csv", 1, None),
        ("a.csv", 2, None),
        ("b.json", None, "$.a"),
        ("b.json", None, "$.z"),
    ]


def test_record_ordering_by_type_then_value():
    d = Deduplicator()
    src = SourceRef(file="a", line=1)
    for t, v in [
        (IOCType.sha256, "b" * 64),
        (IOCType.url, "https://b.example.com/"),
        (IOCType.domain, "b.example.com"),
        (IOCType.ipv4, "192.0.2.9"),
        (IOCType.domain, "a.example.com"),
        (IOCType.md5, "a" * 32),
        (IOCType.sha1, "a" * 40),
    ]:
        d.add(t, v, v, src)
    assert [(r.type.value, r.value) for r in d.records(100)] == [
        ("ipv4", "192.0.2.9"),
        ("domain", "a.example.com"),
        ("domain", "b.example.com"),
        ("url", "https://b.example.com/"),
        ("md5", "a" * 32),
        ("sha1", "a" * 40),
        ("sha256", "b" * 64),
    ]
