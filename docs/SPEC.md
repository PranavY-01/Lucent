# PART B — PRODUCT SPECIFICATION

> Part B is also the content of `docs/SPEC.md`. In M1, create `docs/SPEC.md` containing Part B verbatim (from the heading "PART B" to the end of §B26), followed by an empty "## Clarifications" section. Keep it in sync if any clarification is made.

## B0. Identity

| Item | Value |
|---|---|
| Product name | **Lucent** |
| One-line description | Offline Python CLI that extracts, validates, normalizes and deduplicates potential IOCs from security reports and logs, with source provenance and JSON/CSV export. |
| Series | 7 Days – 7 Cybersecurity Projects |
| Python import package | `lucent_ioc` |
| Distribution name (pyproject `name`) | `lucent-ioc` |
| CLI command | `lucent` |
| Module entry | `python -m lucent_ioc` |
| Report `tool.name` | `"Lucent"` |
| Repository | Confirmed by user in Phase 0 (expected `github.com/PranavY-01/Lucent`) |
| License | MIT |
| Default branch | `main` |
| Starting version | `0.1.0`; release as `1.0.0` |
| Report schema version | `"1.0"` |

The distribution name is `lucent-ioc` because the bare name `lucent` is likely already taken on PyPI. Lucent is not being published to PyPI in v1; the name only matters for `importlib.metadata`.

---

## B1. Purpose and limits

Lucent reads local text files, finds candidate IOCs, recovers documented defanged forms, validates syntax per type, deduplicates equivalent indicators while keeping where each one appeared, and exports structured reports.

Every run answers:

- Which potential indicators were found, of what type, and with what canonical value?
- Where did each appear, and how often?
- How many candidates were rejected, and why?
- Which files were skipped or failed, and why?
- Where were reports written, and did the run complete?

**Extraction is not a verdict.** A valid IP may be private or benign; a valid domain may be legitimate; a hash-shaped string proves nothing about any file. Output says `valid_syntax`, never `malicious`, `safe` or `threat_confirmed`. Lucent makes **no network calls**: no DNS, no HTTP, no lookups.

**Positioning** (for the README): established open-source IOC extractors exist; Lucent does not claim better coverage. Its focus is provenance that survives deduplication, report invariants enforced by tests, explicit rejection reasons, honest status semantics and strictly offline operation.

---

## B2. Scope

### B2.1 v1 goals (all MUST)

1. Local CLI; never executes input content.
2. Extract IPv4, domains, HTTP/HTTPS URLs, MD5, SHA-1, SHA-256.
3. Recover the defanged forms in §B7.1, and only those.
4. Keep detection separate from validation.
5. Preserve original and canonical values.
6. Deduplicate by `(type, canonical value)` while merging provenance.
7. Export JSON and CSV from one report object.
8. Report rejected-candidate counts by reason.
9. Documented, tested exit codes.
10. Unit, golden and integration tests, CI config, README, CHANGELOG.

### B2.2 Non-goals (MUST NOT)

Reputation lookups or scoring; DNS or any network call; URL visits; scanning or probing; malware execution or sandboxing; PCAP, memory or disk forensics; remediation; SIEM integration; dashboards or GUI; databases or cloud services; maliciousness claims; hashing of evidence files; timestamp parsing or timeline reconstruction; IPv6 IOCs; email IOCs; Unicode IDN handling; STIX export.

### B2.3 Tiers

| Tier | Contents |
|---|---|
| **Tier 1 — MUST** (release gate for v1.0.0) | Readers for `.txt` `.log` `.md` `.csv` `.json`; six IOC types; defang set (§B7.1); TLD validation and ambiguous-TLD rule; email masking; URL-host derivation; dedup with `occurrences` and source caps; JSON + CSV export; `--output -` stdout; exit codes; no-overwrite, `--force`, atomic writes; input limits; golden tests; network guard; CI file; README; CHANGELOG; LICENSE |
| **Tier 2 — SHOULD** (only after Tier 1 passes) | `.jsonl` / `.ndjson` input; `--verbose` / `--quiet`; `--max-sources-per-ioc`; `--allow-ambiguous-tlds` |
| **Tier 3 — NOT in v1** | `ip_scope` attribute; plain-text export; benchmarks; JSON key scanning |

Do not implement Tier 3. Tier 2 items not finished go into the CHANGELOG `Unreleased` section.

---

## B3. Terminology

| Term | Meaning |
|---|---|
| Candidate | Substring flagged by a detector; not yet validated |
| Extracted IOC | Candidate that passed validation and was canonicalized |
| Defanged | Contains at least one §B7.1 token in its raw form |
| Rejected candidate | Candidate that failed validation; counted per occurrence by reason |
| Derived IOC | IOC produced from a valid URL's host (`domain` or `ipv4`) |
| Occurrence | One sighting of an IOC |
| Source reference | File plus line, record/column, or JSON path (plus `via` if derived) |
| Canonical value | Normalized value; dedup key and exported `value` |
| Segment | A unit of text from a reader, with its source reference (a line, a CSV cell, a JSON string value) |

---

## B4. Inputs

### B4.1 Formats

| Extension (case-insensitive) | Reader | Segment | Provenance | Tier |
|---|---|---|---|---|
| `.txt`, `.log`, `.md` | Text, streamed line by line | one line (without the newline) | `line` (1-based) | 1 |
| `.csv` | `csv.reader`, streamed | one cell | `record`, `column` | 1 |
| `.json` | `json.load`, recursive | one string value | `path` | 1 |
| `.jsonl`, `.ndjson` | one JSON document per line | one string value | `line` + `path` | 2 |

### B4.2 Encoding

1. Open with `encoding="utf-8-sig"` (strips a BOM), `newline=None` for text files (universal newlines). CSV files use `newline=""` as the `csv` module requires.
2. If a `UnicodeDecodeError` occurs, re-read the whole file with `errors="replace"`, add warning `decode_replacement` for that file, and continue. The file counts as processed.
3. If the file cannot be opened (`OSError`, including `PermissionError`), the file is **failed** (`stage: "read"`), not fatal.

### B4.3 CSV

- First row is the header. Column names come from it. Cells beyond the header width are named `col_<n>` (1-based index). Empty header cells are named `col_<n>` too.
- The header row itself is scanned as `record: 1`.
- `record` counts logical rows from `csv.reader` (a quoted field containing newlines is still one record).
- Before reading, call `csv.field_size_limit(max_file_size_bytes)` so large cells do not raise.
- A `csv.Error` mid-file makes the file **failed** (`stage: "parse"`). Candidates already collected from that file are discarded, so a failed file contributes nothing.

### B4.4 JSON

- Scan only string values. Keys, numbers, booleans and null are not scanned.
- Path format: root `$`; `.name` when the key matches `^[A-Za-z_][A-Za-z0-9_]*$`; otherwise `["key"]` with the key JSON-escaped; `[i]` for array indices. Example: `$.events[2]["src ip"]`.
- JSON sources have `path` only, no `line`.
- `json.JSONDecodeError` makes the file **failed** (`stage: "parse"`). No fallback regex scanning.
- A top-level string (`"foo"`) has path `$`.

### B4.5 JSONL (Tier 2)

- Each non-blank line is parsed separately. Blank lines are ignored.
- A line that fails to parse adds warning `jsonl_line_invalid` (message includes the line number), and reading continues. The file counts as processed.
- Sources have both `line` and `path`.

### B4.6 Discovery

- `INPUT` must exist and be a file or a directory; otherwise fatal (exit 1).
- **Single file:** if its extension is unsupported, fatal (exit 1). An explicitly given symlink is followed.
- **Directory:** examine direct children; with `--recursive`, descend into subdirectories.
  - Do not enter directories whose name starts with `.`.
  - Symlinked directories: not entered; add warning `symlink_skipped`; not counted as discovered files.
  - Symlinked files: counted as **discovered** and **skipped**, warning `symlink_skipped`.
  - Regular files with unsupported extensions: **discovered** and **skipped**, warning `unsupported_extension`.
  - Hidden files with a supported extension are processed normally.
  - Never discover: the resolved `--output` file, and any file inside the resolved `--output-dir`. These are excluded silently and not counted.
- Sort discovered files by their POSIX relative path before processing.
- `files.discovered` = all files counted above. Invariant: `discovered == processed + skipped + failed`.
- If after discovery and reading `processed == 0 and failed == 0`, the run is fatal (exit 1, message "no files were processed"). This covers empty directories, directories with only unsupported files, and a single file skipped for size.

### B4.7 Limits

| Limit | Default | Flag | When exceeded |
|---|---|---|---|
| File size | 50 MB (52,428,800 bytes) | `--max-file-size MB` (integer ≥ 1) | Skipped, warning `over_size_limit` |
| Files per scan | 10,000 | `--max-files N` (integer ≥ 1) | Files beyond N (in sorted order) are skipped; **one** warning `file_limit_reached` |
| URL length | 2,048 chars after trimming | none | Rejected `url_too_long` |
| Sources stored per IOC | 100 | `--max-sources-per-ioc N` (Tier 2) | Truncated after sorting; `sources_truncated: true` |
| Original values per IOC | 20 | none | Truncated after sorting; `original_values_truncated: true` |

The pipeline accepts the file-size limit in **bytes** so tests can use tiny limits; the CLI converts MB to bytes. Content is never silently truncated: a file is fully processed or skipped with a reason.

---

## B5. Detection architecture

### B5.1 Approach (decided)

Detectors run on the **raw** segment text, and their patterns accept defanged separators directly. The raw matched substring is the candidate's `original_value`; normalization happens per candidate. This keeps offsets exact and never rewrites unrelated text. Do **not** normalize whole segments before detection.

### B5.2 Order per segment

1. **URLs:** find URL candidates; trim trailing punctuation (§B6.3); record final spans.
2. **Emails:** find email spans. Emails are not IOCs; spans are recorded for masking only.
3. **Mask:** build a masked copy of the segment where every URL span and email span is replaced by spaces of the same length.
4. **IPv4 and domains:** detect on the **masked** copy.
5. **Hashes:** detect on the **unmasked** segment (so hashes in URL queries are found).
6. **Derive:** for every URL that validates, emit its host as a derived `ipv4` (if the host is an IPv4 literal) or `domain`, with source `via: "url_host"`. The derived candidate's `original_value` is the host exactly as it appeared in the raw URL's authority (e.g. `example[.]com`).

### B5.3 Pattern sketches (non-normative; golden tables in §B15.2 decide correctness)

All compiled once at import, with `re.IGNORECASE` where letters are involved.

```python
DOT = r"(?:\.|\[\.\]|\(\.\)|\{\.\}|\[dot\]|\(dot\))"

IPV4 = rf"(?<![\w.])(?:\d{{1,3}}{DOT}){{3}}\d{{1,3}}(?!\w)(?!{DOT}\w)"

LABEL = r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
TLD = r"[a-z](?:[a-z0-9-]{0,61}[a-z0-9])?"
DOMAIN = rf"(?<![\w.@-])(?:{LABEL}{DOT}){{1,126}}{TLD}(?![\w-])(?!{DOT}\w)"

URL = r"(?<!\w)(?:https?|hxxps?)(?::\/\/|\[:\/\/\]|\[:\]\/\/)[^\s<>\"'`]{1,4096}"

EMAIL = rf"[A-Za-z0-9._%+-]{{1,64}}@(?:{LABEL}{DOT}){{1,126}}{TLD}"

def hex_token(n: int) -> str:
    return rf"(?<![0-9A-Za-z])[0-9A-Fa-f]{{{n}}}(?![0-9A-Za-z])"
MD5, SHA1, SHA256 = hex_token(32), hex_token(40), hex_token(64)
```

The URL pattern deliberately allows up to 4,096 characters so that over-length URLs can be **detected and rejected** as `url_too_long` rather than silently cut.

### B5.4 Regex safety

Every repetition is bounded; no nested unbounded quantifiers; no catastrophic-backtracking constructs. If you change a pattern, keep these properties and keep all golden tests passing.

---

## B6. IOC type contracts

Each validator returns a structured outcome: `ok: bool`, `canonical: str | None`, `reason: str | None`. Validators never print or raise for invalid input.

### B6.1 IPv4

- Normalize: replace every `DOT` token with `.`.
- Validate with `ipaddress.IPv4Address`. Any `ValueError` (out-of-range octet, leading zeros such as `010.0.0.1`) → reject `invalid_ipv4`.
- Canonical: `str(IPv4Address(normalized))`.
- Private, loopback, documentation and reserved addresses are valid. No lookups.

### B6.2 Domains

Validation, in order:

1. Replace `DOT` tokens with `.`; strip **one** trailing `.`; lowercase.
2. At least two labels, total length ≤ 253; else `invalid_domain`.
3. Every label: 1–63 chars of `[a-z0-9-]`, not starting or ending with `-`; else `invalid_domain`.
4. Final label must be in the bundled TLD set (§B6.2.1); else `unknown_tld`.
5. **Ambiguous-TLD rule:** if the final label is in the ambiguous set (§B6.2.2), **and** the candidate is a bare token (not a URL host), **and** it is not defanged, **and** `allow_ambiguous_tlds` is false → reject `ambiguous_file_extension_tld`.

Canonical: lowercase, no trailing dot.

- Unicode domains are not detected. ASCII punycode labels (`xn--…`) are accepted as written and never decoded.
- Emails are masked (§B5.2); neither the address nor its domain is extracted.

#### B6.2.1 TLD data file

- Location: `src/lucent_ioc/data/tlds.txt`.
- Content: an unmodified copy of IANA's list from `https://data.iana.org/TLD/tlds-alpha-by-domain.txt`. Its first line is a comment beginning with `# Version`.
- **You MUST NOT write this file from memory or generate it.** Obtain it one of these ways, as agreed with the user in Phase 0:
  - (a) The user downloads it and places it at the path above; or
  - (b) With explicit user approval, you run `python scripts/update_tlds.py`, which downloads that URL with `urllib.request` and writes the file. This script is a developer tool; it is never imported by the package.
- If the file is absent when you reach M4, stop and ask the user.
- Loader: read via `importlib.resources.files("lucent_ioc") / "data" / "tlds.txt"`; skip lines starting with `#` and blank lines; strip and lowercase entries; cache the set (load once).
- `tld_snapshot` value for reports: the first line's text after `# Version` stripped of whitespace up to the first comma (e.g. the version number IANA writes there). If the line does not match, use `"unknown"`. Do not invent a date.

#### B6.2.2 Ambiguous TLD data file

Location: `src/lucent_ioc/data/ambiguous_tlds.txt`. Exact content:

```text
# TLDs that are also common file extensions.
# A bare, non-defanged domain ending in one of these is rejected
# unless --allow-ambiguous-tlds is set. Only entries also present
# in tlds.txt have any effect.
zip
mov
sh
py
pl
rs
md
ps
so
cab
one
```

Same loader rules as the TLD file. Known trade-off (document in README): bare non-defanged ccTLD domains like `example.pl` or `example.md` are rejected by default. They show up in rejected counts, are accepted when defanged or inside a URL, and can be allowed with `--allow-ambiguous-tlds`.

### B6.3 URLs

**Trailing trimming** (applied to the raw match, repeated until nothing changes):

- Strip one trailing character from `. , ; : ! ?`.
- Strip a trailing `)` if the candidate contains more `)` than `(`. Same for `]`/`[` and `}`/`{`. (Defang tokens like `[.]` and `[://]` contain balanced pairs, so they do not trigger this.)

**Normalization:**

1. Split the trimmed raw URL into scheme, separator and rest with `^(?P<scheme>https?|hxxps?)(?P<sep>://|\[://\]|\[:\]//)(?P<rest>.*)$` (case-insensitive).
2. Scheme: lowercase; `hxxp` → `http`, `hxxps` → `https`. Separator → `://`.
3. Split `rest` at the first `/`, `?` or `#`: authority = before; remainder = from that character on (may be empty).
4. In the **authority only**, replace every `DOT` token with `.`.
5. Split authority at the **last** `@` into userinfo (kept exactly as written) and hostport.
6. In hostport, lowercase the host. Keep the port exactly as written. (An IPv6 literal `[…]` is left as is; validation rejects it.)
7. Rebuild: `scheme + "://" + [userinfo + "@"] + hostport + remainder`. The remainder (path, query, fragment) is **byte-for-byte unchanged**: no decoding, no reordering, no case change, no trailing slash added.

**Validation** (`urllib.parse.urlsplit` on the normalized URL), first failing check wins:

| Check | Reason |
|---|---|
| Length ≤ 2,048 | `url_too_long` |
| Scheme is `http` or `https` | `invalid_url` |
| `hostname` is not None/empty | `invalid_url` |
| Hostname contains `:` (IPv6 literal) | `unsupported_host` |
| Accessing `.port` does not raise, and if present is 1–65535 | `invalid_url` |
| Hostname consisting only of digits and dots must pass §B6.1 | `invalid_url` |
| Otherwise hostname must pass §B6.2 steps 1–4 (ambiguous rule does **not** apply) | `invalid_url` |

Canonical value: the normalized URL. Single-label or internal hosts (`http://intranet/`, `http://server.local/`) are rejected as `invalid_url`; document this limitation.

### B6.4 Hashes

| Type | Length |
|---|---|
| `md5` | 32 hex |
| `sha1` | 40 hex |
| `sha256` | 64 hex |

- Boundary: no ASCII letter or digit immediately before or after (pattern in §B5.3). This makes length precedence unnecessary.
- Canonical: lowercase. Hash candidates that match the pattern are always valid; there is no hash rejection reason.
- Known false positive: other 32-hex strings (undashed GUIDs, tokens) are reported as `md5`. Document it.

---

## B7. Defanging and normalization

### B7.1 Supported (case-insensitive)

| Raw | Becomes | Applies to |
|---|---|---|
| `[.]` `(.)` `{.}` `[dot]` `(dot)` | `.` | IPv4, domains, URL authority |
| `hxxp` | `http` | URL scheme |
| `hxxps` | `https` | URL scheme |
| `[://]` and `[:]//` | `://` | URL separator |

A candidate is **defanged** if its raw text contains any token above.

### B7.2 Not supported (do not attempt)

Spaced dots (`example . com`), words (`example dot com`), `[@]`, backslash-escaped dots, partial brackets (`example[.com`), Unicode look-alikes, `fxp://`, `meow://`, any other scheme rewrite.

### B7.3 Rules

- Normalization is idempotent: a canonical value normalizes to itself.
- Never remove arbitrary characters to force validation, never touch URL path/query/fragment, never merge types, never drop the original value.

---

## B8. Pipeline and deduplication

### B8.1 Pipeline stages

1. CLI parses and checks options (§B10); resolves paths; checks path conflicts (§B12.1).
2. Discover files; apply limits.
3. For each file: read into segments. A per-file exception becomes a failed-file error; the scan continues.
4. Detect candidates per §B5.2.
5. Normalize, validate, canonicalize. Each rejected candidate increments `rejected[reason]` (counted **per occurrence**).
6. Derive URL hosts.
7. Deduplicate.
8. Build the report object; validate invariants (§B9.4).
9. Export from that one object.
10. Print terminal summary; exit with the mapped code (§B10.4).

### B8.2 Candidate model

Fields: `type`, `original_value`, `source` (SourceRef), `start`, `end` (offsets within the segment), `defanged: bool`, `derived: bool`.

### B8.3 Deduplication

- Key `(type, canonical_value)` in a `dict`.
- Every valid sighting increments `occurrences` (repeats on the same line count).
- `sources`: a set keyed by full identity `(file, line, record, column, path, via)`.
- `original_values`: a set of distinct raw strings.
- Never deduplicate across types.
- At report build:
  - sort sources by `(file, line or 0, record or 0, column or "", path or "", via or "")`;
  - `source_count` = number of unique sources; keep the first `max_sources_per_ioc`; `sources_truncated = source_count > max`;
  - sort `original_values` lexicographically; keep the first 20; set `original_values_truncated`.

---

## B9. Data contracts

### B9.1 Models (Pydantic v2, in `models.py`)

```text
IOCType (str enum, in this order): ipv4, domain, url, md5, sha1, sha256
ScanStatus (str enum): completed, completed_with_warnings, partial

SourceRef:  file: str
            line: int | None = None
            record: int | None = None
            column: str | None = None
            path: str | None = None
            via: Literal["url_host"] | None = None

IOCRecord:  type: IOCType
            value: str
            validation_status: Literal["valid_syntax"] = "valid_syntax"
            occurrences: int (>= 1)
            source_count: int (>= 1)
            sources_truncated: bool
            original_values: list[str]
            original_values_truncated: bool
            sources: list[SourceRef]

Warning:    code: str, path: str, message: str
ErrorEntry: path: str, stage: Literal["read","parse","export"], error_type: str,
            message: str, recoverable: bool

FileCounts: discovered, processed, skipped, failed (all int >= 0)
Limits:     max_file_size_bytes, max_files, max_sources_per_ioc (int)
ScanInfo:   timestamp_utc: str, input: str, recursive: bool, strict: bool,
            allow_ambiguous_tlds: bool, status: ScanStatus, files: FileCounts,
            limits: Limits, tld_snapshot: str
Rejected:   total: int, by_reason: dict[str, int]
Summary:    total_unique_iocs: int, by_type: dict[str, int], rejected_candidates: Rejected
ToolInfo:   name: str = "Lucent", version: str
Report:     schema_version: str = "1.0", tool: ToolInfo, scan: ScanInfo,
            summary: Summary, iocs: list[IOCRecord],
            warnings: list[Warning], errors: list[ErrorEntry]
```

Name the warning model something that does not shadow Python's built-in `Warning` (e.g. `ScanWarning`); the JSON key stays `warnings`.

When serializing, `SourceRef` fields that are `None` are **omitted** (use `model_dump(mode="json", exclude_none=True)`). Nothing else is None.

### B9.2 Field semantics

- `scan.input`: base name of `INPUT` (file name, or directory name). Never an absolute path.
- `SourceRef.file`: for a directory input, path relative to the input directory with `/` separators on every OS (`PurePath.as_posix()`); for a single-file input, its base name.
- `scan.status`: `completed` if no warnings and no errors; `partial` if `files.failed > 0`; otherwise `completed_with_warnings`.
- `summary.by_type`: always contains all six types in enum order, zeros included.
- `summary.rejected_candidates.by_reason`: only reasons with count > 0, keys sorted alphabetically; `{}` if none.
- Rejection reasons: `invalid_ipv4`, `invalid_domain`, `unknown_tld`, `ambiguous_file_extension_tld`, `invalid_url`, `unsupported_host`, `url_too_long`.
- Warning codes: `unsupported_extension`, `symlink_skipped`, `over_size_limit`, `file_limit_reached`, `decode_replacement`, `jsonl_line_invalid`.
- `timestamp_utc`: `YYYY-MM-DDTHH:MM:SSZ` (seconds precision, UTC), from an injectable clock.
- `tool.version`: from `importlib.metadata.version("lucent-ioc")`, falling back to `"0.0.0+unknown"` if the package metadata is unavailable.

### B9.3 Report example (shape; values are placeholders)

```json
{
  "schema_version": "1.0",
  "tool": {"name": "Lucent", "version": "1.0.0"},
  "scan": {
    "timestamp_utc": "2026-10-28T12:00:00Z",
    "input": "incident_report.txt",
    "recursive": false,
    "strict": false,
    "allow_ambiguous_tlds": false,
    "status": "completed",
    "files": {"discovered": 1, "processed": 1, "skipped": 0, "failed": 0},
    "limits": {"max_file_size_bytes": 52428800, "max_files": 10000, "max_sources_per_ioc": 100},
    "tld_snapshot": "<from tlds.txt header>"
  },
  "summary": {
    "total_unique_iocs": 0,
    "by_type": {"ipv4": 0, "domain": 0, "url": 0, "md5": 0, "sha1": 0, "sha256": 0},
    "rejected_candidates": {"total": 0, "by_reason": {}}
  },
  "iocs": [],
  "warnings": [],
  "errors": []
}
```

### B9.4 Report invariants (enforce with a model validator AND tests)

1. `total_unique_iocs == len(iocs)`.
2. `sum(by_type.values()) == total_unique_iocs`; `by_type` has exactly the six keys.
3. `sum(by_reason.values()) == rejected_candidates.total`.
4. Every IOC has `validation_status == "valid_syntax"`.
5. No duplicate `(type, value)`.
6. For every IOC: `occurrences >= source_count >= len(sources) >= 1`.
7. `files.discovered == processed + skipped + failed`.
8. Status rule of §B9.2 holds.
9. `iocs` sorted by enum order of `type`, then `value`.

### B9.5 JSON output

`json.dumps(report_dict, indent=2, ensure_ascii=False) + "\n"`, UTF-8. Key order follows model field order.

### B9.6 CSV output

Header and column order exactly:

```text
type,value,validation_status,occurrences,source_count,original_values,sources
```

- One row per IOC, in report order.
- `original_values` and `sources` cells: `json.dumps(list, ensure_ascii=False, separators=(",", ":"))` (sources with None fields omitted).
- Write with `csv.writer`, file opened `newline=""`, `encoding="utf-8"` (no BOM).
- Formula guard: any cell whose text starts with `=`, `+`, `-`, `@`, `\t` or `\r` is prefixed with `'`, in CSV only. JSON values are never altered.

### B9.7 Determinism

With a frozen clock, two runs on the same input produce byte-identical JSON and CSV on the same machine, and identical `sources` paths on every OS.

---

## B10. CLI contract

### B10.1 Commands

```text
lucent scan INPUT
    [--recursive]
    [--format json|csv|both]
    [--output FILE | --output -]
    [--output-dir DIR]
    [--force]
    [--strict]
    [--max-file-size MB]          default 50
    [--max-files N]               default 10000
    [--max-sources-per-ioc N]     Tier 2, default 100
    [--allow-ambiguous-tlds]      Tier 2
    [--verbose | --quiet]         Tier 2

lucent --version                  prints "lucent <version>" and exits 0
lucent --help
python -m lucent_ioc ...          same as `lucent`
```

Implementation notes:

- Typer collapses an app with a single command into the root command. Define `@app.callback()` (hosting the eager `--version` option) so `scan` stays an explicit subcommand. Verify `lucent --help` lists `scan`.
- `--format` has no default at the option level (`None`); treat `None` as `json`.

### B10.2 Option validation and output rules

| Situation | Result |
|---|---|
| `--output` and `--output-dir` both given | Usage error, exit 2 |
| `--format both` with `--output` | Usage error, exit 2 |
| `--format both` without `--output-dir` | Usage error, exit 2 |
| `--format csv` or `both` with no destination | Usage error, exit 2 |
| `--verbose` and `--quiet` together | Usage error, exit 2 |
| No destination (and format omitted or `json`) | Terminal only: summary + IOC table capped at 50 rows with "showing 50 of N" when truncated. No files written. |
| `--output FILE` | Write the one format to FILE; create missing parent directories |
| `--output -` | Write the one format to stdout; all human-readable output goes to **stderr** |
| `--output-dir DIR` | Write `lucent_iocs.json` and/or `lucent_iocs.csv` into DIR; create DIR if missing |
| Any target output file already exists | Fatal exit 1 before writing anything, unless `--force` |
| Any output path resolves to an input file | Fatal exit 1, even with `--force` |

All file writes are atomic: `tempfile.NamedTemporaryFile(dir=<target dir>, delete=False)`, write, flush, close, `os.replace(temp, target)`. Remove the temp file on failure.

Human-readable output goes to stdout normally, and to stderr when `--output -` is used. Fatal errors always go to stderr as `Error: <message>`.

### B10.3 Exit codes

| Code | When |
|---|---|
| 0 | Status `completed` or `completed_with_warnings` (without `--strict`). Zero IOCs is still 0. |
| 1 | Fatal: missing/invalid INPUT, unsupported single-file extension, no files processed, path conflict, existing output without `--force`, or no requested output could be written. |
| 2 | Usage error (Click/Typer convention; raise `click.UsageError` or `typer.BadParameter`). |
| 3 | Status `partial`; or one of two requested exports failed; or `--strict` with any warning. |

- `--strict` changes only the exit-code mapping, never processing or output content.
- With `--format both`: if one export fails, keep the other, print the error, exit 3. If both fail, exit 1. The written file does not record later export failures.

### B10.4 Terminal summary content

Input; files discovered / processed / skipped / failed; total unique IOCs and counts by type; rejected total and by reason; each warning and error on one line; output paths; final status. Every number comes from the report object.

- `--quiet` (Tier 2): print only errors and the final status line.
- `--verbose` (Tier 2): additionally print one line per file processed, and full tracebacks for per-file errors.
- Without `--verbose`, never print tracebacks or file contents.

---

## B11. Error handling

- **Recoverable (per file, scan continues):** unreadable file, malformed JSON, CSV parse error, over-size file, unsupported extension in a directory, symlink in traversal, invalid JSONL line, one of two exports failing.
- **Fatal (exit 1, no report written):** listed in §B10.3.
- Error and warning messages name the file (relative path) and the problem. Never include file contents or full input lines.
- Per-file failures add an `ErrorEntry` with `recoverable: true`.

---

## B12. Security and privacy

MUST:

1. Treat input as untrusted; never `eval`, `exec`, `pickle.load` or otherwise execute it.
2. Make no network calls (enforced by §B15.3).
3. Never overwrite an input file; refuse existing outputs without `--force`; write atomically.
4. Not follow symlinks during traversal.
5. Keep absolute paths out of reports and normal output.
6. Not print or log input lines.
7. Bound regex work and input sizes.
8. Apply the CSV formula guard.
9. Use only synthetic samples: `example.com`, `example.org`, `example.net` and their subdomains, and documentation IPs `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`.

### B12.1 Path-conflict check

Before any write: resolve every discovered input file and every output target with `Path.resolve()`. If any output equals any input, exit 1 before writing.

---

## B13. Repository layout and module responsibilities

### B13.1 Layout (create exactly this)

```text
<repo root>/
├── .github/
│   └── workflows/
│       └── ci.yml
├── docs/
│   ├── SPEC.md
│   └── architecture.md
├── samples/
│   ├── incident_report.txt
│   ├── sample_logs.log
│   ├── sample_events.json
│   └── sample_iocs.csv
├── scripts/
│   └── update_tlds.py
├── src/
│   └── lucent_ioc/
│       ├── __init__.py
│       ├── __main__.py
│       ├── cli.py
│       ├── config.py
│       ├── reader.py
│       ├── extractors.py
│       ├── normalizer.py
│       ├── validator.py
│       ├── deduplicator.py
│       ├── models.py
│       ├── pipeline.py
│       ├── exporters.py
│       └── data/
│           ├── tlds.txt
│           └── ambiguous_tlds.txt
├── tests/
│   ├── conftest.py
│   ├── fixtures/
│   ├── test_reader.py
│   ├── test_extractors.py
│   ├── test_normalizer.py
│   ├── test_validator.py
│   ├── test_deduplicator.py
│   ├── test_exporters.py
│   ├── test_pipeline.py
│   ├── test_cli.py
│   └── test_golden.py
├── .gitattributes
├── .gitignore
├── CHANGELOG.md
├── LICENSE
├── README.md
└── pyproject.toml
```

### B13.2 Responsibilities

| Module | Does | Must not |
|---|---|---|
| `__init__.py` | Expose `__version__` (§B9.2) | Import heavy modules |
| `__main__.py` | `from lucent_ioc.cli import app; app()` | Anything else |
| `cli.py` | Typer app, callback, `--version`, option checks, Rich output, exit-code mapping | Contain extraction logic |
| `config.py` | Defaults, limits, warning codes, rejection reasons, type order, output filenames | Do I/O |
| `reader.py` | Discovery, limits, symlink/hidden rules, encoding, format readers yielding `(text, SourceRef)` | Detect IOCs |
| `extractors.py` | Compiled patterns, URL trimming, masking, candidate detection with offsets | Validate or do I/O |
| `normalizer.py` | §B7.1 transforms, URL authority normalization, defanged detection | Touch URL remainder |
| `validator.py` | Per-type validation, TLD/ambiguous sets loading, outcomes with reasons | Print or raise on bad input |
| `deduplicator.py` | Keying, merging, occurrences, sorting, caps | Change values |
| `models.py` | Pydantic models, enums, report invariant validator | Format terminal output |
| `pipeline.py` | Orchestration, warning/error collection, summary, status, injectable clock; returns the Report | Print, or parse file formats |
| `exporters.py` | JSON/CSV serialization, formula guard, atomic writes, directory creation, stdout writing | Recompute counts |

Public pipeline entry point (signature to implement):

```python
def run_scan(
    input_path: Path,
    *,
    recursive: bool = False,
    strict: bool = False,
    allow_ambiguous_tlds: bool = False,
    max_file_size_bytes: int = 52_428_800,
    max_files: int = 10_000,
    max_sources_per_ioc: int = 100,
    excluded_paths: Sequence[Path] = (),
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> Report: ...
```

`excluded_paths` carries the resolved output file/dir so discovery skips them. Fatal conditions raise a dedicated exception (e.g. `LucentFatalError`) that the CLI turns into exit 1.

---

## B14. Packaging and dependencies

### B14.1 `pyproject.toml` (use this; adjust version bounds only if installation fails, and report it)

```toml
[build-system]
requires = ["hatchling>=1.24"]
build-backend = "hatchling.build"

[project]
name = "lucent-ioc"
version = "0.1.0"
description = "Lucent: offline CLI that extracts, validates, normalizes and deduplicates potential IOCs from reports and logs."
readme = "README.md"
license = "MIT"
requires-python = ">=3.11"
dependencies = [
  "typer>=0.12",
  "rich>=13",
  "pydantic>=2.6",
]

[project.optional-dependencies]
dev = [
  "pytest>=8",
  "pytest-cov>=5",
  "ruff>=0.5",
]

[project.scripts]
lucent = "lucent_ioc.cli:app"

[tool.hatch.build.targets.wheel]
packages = ["src/lucent_ioc"]

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.ruff]
line-length = 100
target-version = "py311"
```

- Version lives only in `pyproject.toml`.
- Verify that `data/tlds.txt` and `data/ambiguous_tlds.txt` are inside the built wheel (build it with `python -m pip wheel . -w dist --no-deps` and list the wheel contents, then delete `dist/`).
- Runtime dependencies are exactly Typer, Rich and Pydantic. No HTTP, DNS, database, web or async libraries.

### B14.2 Install

```bash
python -m venv .venv
# activate (.venv\Scripts\activate on Windows PowerShell; source .venv/bin/activate otherwise)
python -m pip install -e ".[dev]"
```

### B14.3 Known version traps (verify, do not guess)

- **Click `CliRunner` stderr:** Click 8.2+ captures stderr separately by default (`result.stdout`, `result.stderr`); Click 8.1 needs `CliRunner(mix_stderr=False)`. Check the installed Click version and write tests accordingly.
- **Typer single-command collapse:** see §B10.1.
- **Pydantic v2 APIs:** use `model_dump`, `model_validate`, `model_validator`; not v1 `dict()`/`validator`.
- **`importlib.resources`:** use `files()` API (Python 3.9+).

---

## B15. Testing

### B15.1 Coverage required

| Test file | Must cover |
|---|---|
| `test_reader.py` | UTF-8, BOM, decode fallback warning, empty file, CSV header/record/column, multi-line CSV field, `col_<n>`, JSON paths incl. quoted keys and arrays, top-level string, malformed JSON failure, CSV parse failure, unsupported/symlink/hidden-dir rules, size and file-count limits, output exclusion, sorted discovery, unreadable file (via monkeypatched `open` raising `PermissionError`) |
| `test_extractors.py` | Detection side of golden cases, masking, offsets, URL trimming |
| `test_normalizer.py` | Each §B7.1 form, authority-only scope, userinfo/port preservation, idempotence, defanged flag |
| `test_validator.py` | Each rejection reason at least once; TLD loader; `tld_snapshot` parsing incl. `"unknown"` fallback |
| `test_deduplicator.py` | Repeats, case folding, cross-type separation, occurrences vs source_count, `via` in identity, caps and flags, ordering |
| `test_exporters.py` | JSON round-trip through `Report.model_validate`, CSV header/rows, JSON-encoded cells, formula guard, atomic write leaves no temp file, `--force`, refusal on existing file, write failure handling |
| `test_cli.py` | Every row of §B10.2 and §B10.3; `--version`; `--output -` stdout contains only the JSON; `python -m lucent_ioc --help` works |
| `test_pipeline.py` | All §B9.4 invariants on every sample and fixture; partial status; frozen-clock determinism |
| `test_golden.py` | Every row of §B15.2, parametrized |

### B15.2 Golden cases (normative)

Each row is one segment of text. "Nothing" means no IOC and no rejection. `H32`, `H40`, `H64` are hex strings of that length (use distinct real-looking values in tests, e.g. `d41d8cd98f00b204e9800998ecf8427e` for H32).

**IPv4**

| Input | Expected |
|---|---|
| `203.0.113.10` | `ipv4: 203.0.113.10` |
| `203.0.113[.]10` | `ipv4: 203.0.113.10` |
| `203.0.113.10:8080` | `ipv4: 203.0.113.10` |
| `Seen from 192.0.2.1.` | `ipv4: 192.0.2.1` |
| `999.1.1.1` | rejected `invalid_ipv4` |
| `010.0.0.1` | rejected `invalid_ipv4` |
| `1.2.3.4.5` | nothing |
| `v1.2.3.4` | nothing |

**Domains**

| Input | Expected |
|---|---|
| `example.com` | `domain: example.com` |
| `Example[.]COM` | `domain: example.com`, original `Example[.]COM` |
| `sub.example(.)org` | `domain: sub.example.org` |
| `example{.}net` | `domain: example.net` |
| `example[dot]net` | `domain: example.net` |
| `example(DOT)net` | `domain: example.net` |
| `See example.com.` | `domain: example.com` |
| `xn--80ak6aa92e.com` | `domain: xn--80ak6aa92e.com` |
| `report.pdf` | rejected `unknown_tld` |
| `version 2.4.1` | nothing |
| `invoice.zip` | rejected `ambiguous_file_extension_tld` |
| `invoice[.]zip` | `domain: invoice.zip` |
| `invoice.zip` with `allow_ambiguous_tlds=True` | `domain: invoice.zip` |
| `analyst@example.org` | nothing |

**URLs**

| Input | Expected |
|---|---|
| `https://example.com/a?b=1` | `url: https://example.com/a?b=1`; `domain: example.com` (via url_host) |
| `hxxps://example[.]com/test` | `url: https://example.com/test`; `domain: example.com` |
| `hXXp[:]//example[.]com/x` | `url: http://example.com/x`; `domain: example.com` |
| `hxxp[://]example[.]com` | `url: http://example.com`; `domain: example.com` |
| `(see https://example.com/page).` | `url: https://example.com/page`; `domain: example.com` |
| `https://en.wikipedia.org/wiki/Foo_(bar)` | `url: https://en.wikipedia.org/wiki/Foo_(bar)`; `domain: en.wikipedia.org` |
| `HTTPS://EXAMPLE.COM/Path?Q=A` | `url: https://example.com/Path?Q=A`; `domain: example.com` |
| `https://example.com/a[.]b` | `url: https://example.com/a[.]b`; `domain: example.com` |
| `https://203.0.113.10:8443/login` | `url: https://203.0.113.10:8443/login`; `ipv4: 203.0.113.10` (via url_host) |
| `https://bank.example.com@evil.example.org/` | `url: https://bank.example.com@evil.example.org/`; `domain: evil.example.org` |
| `https://example.com/files/other.com` | `url: https://example.com/files/other.com`; `domain: example.com`; no `other.com` |
| `ftp://example.com/file` | `domain: example.com`; no url |
| `http://intranet/` | rejected `invalid_url` |
| `https://[2001:db8::1]/` | rejected `unsupported_host` |
| `https://example.com:99999/` | rejected `invalid_url` |
| `https://example.com/` + 2,100 × `a` | rejected `url_too_long` |

**Hashes**

| Input | Expected |
|---|---|
| `H32` | `md5`, lowercase |
| `H40` | `sha1` |
| `H64` | `sha256` |
| `H64` in upper/mixed case | `sha256`, lowercase value |
| `sha256=H64` | `sha256` |
| `https://example.com/d?h=H64` | `url`, `domain: example.com`, `sha256` |
| 65 hex chars | nothing |
| 31 hex chars | nothing |
| `abc` + `H32` + `xyz` | nothing |
| 64 chars, one of them `g` | nothing |

**Deduplication (multi-line inputs)**

| Input | Expected |
|---|---|
| `203.0.113.10` on lines 1 and 3 | one record, `occurrences: 2`, 2 sources |
| `203.0.113.10 203.0.113.10` on one line | one record, `occurrences: 2`, `source_count: 1` |
| `example.com` (line 1) and `EXAMPLE[.]com` (line 2) | one domain, `original_values: ["EXAMPLE[.]com", "example.com"]` |
| `https://example.com/` (line 1) and `example.com` (line 2) | one url; one domain with 2 sources, line 1 with `via: "url_host"` |

### B15.3 Network guard (must exist in `tests/conftest.py`)

```python
import socket
import pytest

@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    def guard(*args, **kwargs):
        raise RuntimeError("Network access attempted during tests")
    monkeypatch.setattr(socket.socket, "connect", guard)
    monkeypatch.setattr(socket, "getaddrinfo", guard)
    monkeypatch.setattr(socket, "create_connection", guard)
```

`conftest.py` also provides a frozen clock fixture returning `datetime(2026, 10, 28, 12, 0, 0, tzinfo=timezone.utc)`.

### B15.4 Integration

Use `typer.testing.CliRunner` on every file in `samples/` and on a fixture directory containing a good text file, a malformed JSON, an empty file, an oversize file (with a tiny limit via the pipeline), and an unsupported `.bin` file. Assert IOC sets, counts, sources, status, exit codes, invariants, JSON/CSV agreement (same IOC set and order), and byte-identical output across two runs with the frozen clock. The §B23 demo is its own integration test (ignore `tld_snapshot`).

### B15.5 Allowed platform skips

- Symlink tests: `pytest.skip` if `os.symlink` raises `OSError`/`NotImplementedError` (Windows without privilege).
- Nothing else may be skipped.

---

## B16. Repository files, version control and release

The builder creates these files. The **user** performs all Git operations (Part A, A1).

### B16.1 `.gitignore` (exact)

```gitignore
__pycache__/
*.py[cod]
.venv/
venv/
.env
.pytest_cache/
.ruff_cache/
.coverage
htmlcov/
build/
dist/
*.egg-info/
reports/
lucent_iocs.json
lucent_iocs.csv
*.log
!samples/**/*.log
!tests/fixtures/**/*.log
.DS_Store
Thumbs.db
```

Note: `!samples/**/*.log` re-includes logs under `samples/`. Verify with `git status` (read-only) after creating `samples/sample_logs.log` that the file shows as untracked, not ignored. If the repository is not initialized yet, tell the user to check it after `git init`.

### B16.2 `.gitattributes` (exact)

```gitattributes
* text=auto eol=lf
```

### B16.3 `LICENSE`

Standard MIT License text, `Copyright (c) 2026 <holder confirmed in Phase 0>`.

### B16.4 `CHANGELOG.md`

Keep a Changelog format:

```markdown
# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

### Added
- (entries added as milestones land)
```

Add entries at each milestone. At release, move them to `## [1.0.0] - <date>`.

### B16.5 CI: `.github/workflows/ci.yml` (exact)

```yaml
name: CI
on:
  push:
  pull_request:
jobs:
  test:
    strategy:
      fail-fast: false
      matrix:
        os: [ubuntu-latest, windows-latest]
        python: ["3.11", "3.12", "3.13"]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: ${{ matrix.python }}
      - run: python -m pip install -e ".[dev]"
      - run: ruff check .
      - run: python -m pytest --cov=lucent_ioc
```

You only create this file. It runs on GitHub when the user pushes. Never claim CI passed; you cannot see it. Ask the user to report the CI result after their push.

### B16.6 Versioning

- Tool: SemVer. `0.1.0` during development; `1.0.0` at release.
- Report: `schema_version` `"1.0"`, independent of tool version.
- Spec: `docs/SPEC.md`; clarifications appended under "Clarifications" with date.

### B16.7 Branch model (commands given to the user)

One branch per milestone, named as in §B17, merged into `main` with `--no-ff`. The user creates branches, commits, merges and pushes from your handoff blocks.

### B16.8 Release (M6)

Builder does (file edits only):

1. Set `version = "1.0.0"` in `pyproject.toml`.
2. Move CHANGELOG entries to `## [1.0.0] - <today's date>`.
3. Re-run the full suite, ruff, the wheel-content check and the §B23 demo; record real results.

Then hand the user:

```bash
git status
git switch -c feat/m6-release
git add <exact paths>
git commit -m "chore(release): v1.0.0"
git switch main
git merge --no-ff feat/m6-release -m "merge: M6 reliability and release"
git push origin main
git tag -a v1.0.0 -m "Lucent v1.0.0"
git push origin v1.0.0
```

and instruct the user to create a GitHub Release from tag `v1.0.0` on github.com, pasting the `[1.0.0]` CHANGELOG section as notes, after confirming CI is green.

A release is not done until the tag exists. You do not create it.

---

## B17. Milestones

| # | Branch | Deliverables | Exit condition | Suggested commit(s) |
|---|---|---|---|---|
| M1 | `feat/m1-skeleton` | `pyproject.toml`, package skeleton (`__init__`, `__main__`, `cli` with callback, `--version`, `scan` stub that prints "not implemented yet" and exits 1), `config.py`, `models.py` (all models), `docs/SPEC.md`, `.gitignore`, `.gitattributes`, `LICENSE`, `CHANGELOG.md`, `ci.yml`, minimal `README.md`, `tests/conftest.py`, a first test for `--version` and `--help` | `.venv` install works; `lucent --help` lists `scan`; `lucent --version` prints the version; `python -m lucent_ioc --help` works; tests and ruff pass | `build: add project skeleton, packaging and CI config` |
| M2 | `feat/m2-readers` | `reader.py` (discovery, limits, symlinks, encoding, TXT/LOG/MD, CSV, JSON), samples, reader tests | Samples yield segments with correct provenance; all reader tests pass | `feat(reader): add discovery, limits and format-aware readers` |
| M3 | `feat/m3-detection` | `extractors.py` (patterns, trimming, masking, offsets), detection tests and golden detection rows | Detection-side golden rows pass | `feat(extractors): add defang-aware detectors with url/email masking` |
| M4 | `feat/m4-validation` | `normalizer.py`, `validator.py`, data files (TLD file obtained per §B6.2.1), `scripts/update_tlds.py`, all golden rows | Every §B15.2 row passes | `feat(validator): add normalization, TLD checks and rejection reasons` |
| M5 | `feat/m5-reports` | `deduplicator.py`, `pipeline.py`, `exporters.py`, full `scan` command, output rules, exit codes | Invariant, exporter and CLI tests pass; JSON and CSV agree | `feat(pipeline): add dedup, report building, exporters and scan command` |
| M6 | `feat/m6-release` | Integration tests, §B23 demo test, path-conflict tests, `docs/architecture.md`, full README, CHANGELOG, version 1.0.0, wheel check | §B18 all ticked (except items only the user can do); release handoff given | `test: add integration and demo tests`, `docs: complete README and architecture`, `chore(release): v1.0.0` |

Tier 2 items, if attempted, go in an extra branch `feat/tier2-extras` after M5 and before M6, only if the user agrees.

### B17.1 Sample files (create in M2)

- `samples/incident_report.txt`: exactly the §B23 input.
- `samples/sample_logs.log`: 10–20 synthetic log lines mixing IPv4 (documentation ranges), defanged URLs, a hash, an invalid IP, a filename like `update.exe`.
- `samples/sample_events.json`: nested object with an `events` array of messages containing URLs, a domain and a hash, plus a key with a space.
- `samples/sample_iocs.csv`: header row plus rows with an `indicator` column and a `notes` column, including a multi-line quoted field.

All synthetic, reserved names and documentation IPs only.

---

## B18. Acceptance checklist (definition of done for v1.0.0)

**Functional**

- [ ] Reads `.txt`, `.log`, `.md`, `.csv`, `.json` per §B4.
- [ ] All six IOC types extracted; every §B15.2 row passes.
- [ ] Exactly the §B7.1 defang forms supported.
- [ ] TLD validation and ambiguous rule behave as specified.
- [ ] URL hosts derived with `via: "url_host"`.
- [ ] Dedup merges sources, counts occurrences; caps and flags correct.
- [ ] JSON and CSV come from one Report and agree.
- [ ] All §B9.4 invariants hold on every sample and fixture.
- [ ] Every §B10.2 rule and §B10.3 exit code tested.
- [ ] Network guard active; no network use.

**Engineering**

- [ ] Fresh `.venv` install works; data files present in the wheel.
- [ ] `ruff check .` clean; full test suite passes locally.
- [ ] Deterministic output with frozen clock.
- [ ] Input overwrite impossible; atomic writes in place.
- [ ] README complete (§B19); every README command and output was produced by an actual run.
- [ ] CHANGELOG has `[1.0.0]`; `docs/SPEC.md` matches behaviour.
- [ ] Samples synthetic; no secrets or real data.
- [ ] (User) CI green on GitHub after push.
- [ ] (User) `v1.0.0` tag pushed and GitHub Release created.

---

## B19. README outline

1. `# Lucent` and the one-line description
2. Why Lucent (positioning, §B1)
3. Features
4. Scope and non-goals
5. Installation (`python -m venv`, `pip install -e ".[dev]"`; clone URL from Phase 0)
6. Usage: only commands you ran, with real output
7. Sample input and output (§B23, real output)
8. Supported IOC types, defang forms, and unsupported forms
9. Validation rules: TLD snapshot (value from `tld_snapshot`), ambiguous-TLD trade-off, email policy, IPv6/IDN unsupported, internal hostnames rejected
10. Report schema (JSON, CSV), `schema_version`
11. Exit codes and `--strict`
12. Architecture (mermaid flowchart of the pipeline stages)
13. Testing (`python -m pytest`) and CI
14. Security and privacy
15. Limitations and known false positives (32-hex tokens as MD5, ambiguous TLDs, no IPv6/emails)
16. Roadmap (§B21)
17. License

Wording rules: say "extracts potential IOCs" and "validates syntax". Never "detects malicious", "threat detection engine", "guaranteed accurate". No badges for things that do not exist yet (no PyPI badge; a CI badge only with the confirmed repo URL).

---

## B20. Risks and mitigations

| Risk | Mitigation |
|---|---|
| Filenames as domains | TLD set, ambiguous rule, golden negatives |
| Legit ccTLDs rejected | Defang/URL exemptions, visible rejected counts, `--allow-ambiguous-tlds`, docs |
| Paths/emails as domains | Span masking |
| 32-hex tokens as MD5 | Alphanumeric boundaries; documented |
| URL punctuation errors | Balanced trimming; golden cases |
| Over-normalization | Authority-only defang; idempotence tests |
| Lost provenance | Merge-not-replace; `via` in identity |
| Huge source lists | Caps with counts and flags |
| Output disagreement | One Report object; invariants |
| One bad file stops batch | Per-file isolation; `partial`; exit 3 |
| Evidence overwritten | Path-conflict check; `--force`; atomic writes |
| Regex blowup | Bounded patterns; size limits |
| Fabricated TLD list | §B6.2.1 procurement rule |
| Builder runs Git writes | Part A, A1 |

---

## B21. Roadmap (not in v1)

v1.1: Tier 2 leftovers, JSON key scanning, `ip_scope`, plain-text export, more defang forms, include/exclude globs, benchmarks.
v2: IPv6, emails, IDN with explicit IDNA policy, STIX 2.1, opt-in enrichment, confidence annotations, integration with later series tools.

---

## B22. Decisions register (authoritative)

| # | Topic | Decision |
|---|---|---|
| D-1 | Detection | Defang-aware detection on raw text; per-candidate normalization |
| D-2 | Order | URL → email mask → IPv4/domain on masked text → hashes on unmasked → URL-host derivation |
| D-3 | Output options | `--output`/`--output-dir` exclusive; `both` needs `--output-dir`; `--output -` = stdout; csv/both need a destination |
| D-4 | Output names | `lucent_iocs.json`, `lucent_iocs.csv` |
| D-5 | Overwrite | Refuse existing unless `--force`; never overwrite inputs; atomic writes |
| D-6 | Encoding | `utf-8-sig`; fallback `errors="replace"` + warning |
| D-7 | Limits | 50 MB/file, 10,000 files, 2,048-char URLs, 100 sources/IOC, 20 originals/IOC |
| D-8 | Unsupported | Skip+warn in directories; fatal for single file |
| D-9 | Symlinks/hidden | Not followed in traversal; dot-dirs not entered; hidden files processed |
| D-10 | Domains | Label rules + IANA TLD set + ambiguous rule with defang/URL exemptions |
| D-11 | Trailing dot | Stripped |
| D-12 | IDN | Unicode not detected; punycode accepted as written |
| D-13 | Emails | Masked; not extracted |
| D-14 | URL normalization | Scheme + authority only; userinfo and port kept; remainder untouched |
| D-15 | URL hosts | Derived as domain/ipv4 with `via: "url_host"` |
| D-16 | IPv6 hosts | `unsupported_host` |
| D-17 | Hashes | Exact length, no adjacent ASCII alphanumerics |
| D-18 | Sources | `file` always; `line`; `record`+`column`; `path`; `via`; None omitted |
| D-19 | JSON lines | No line numbers for `.json` |
| D-20 | Rejections | Counted per occurrence by reason; no list |
| D-21 | Exit codes | 0 / 1 / 2 / 3 per §B10.3 |
| D-22 | Partial export | Keep successful export; exit 3 |
| D-23 | Strict | Any warning → exit 3; processing unchanged |
| D-24 | Zero IOCs | Valid empty report; exit 0 |
| D-25 | Nothing processed | Fatal; exit 1 |
| D-26 | Sort | Type enum order, then value |
| D-27 | CSV | One row per IOC; JSON-encoded list cells; formula guard |
| D-28 | Versions | Tool SemVer; `schema_version` "1.0"; spec in `docs/SPEC.md` |
| D-29 | Git | User runs all Git writes; builder supplies commands; milestone branches `--no-ff` |
| D-30 | CI | GitHub Actions, Ubuntu + Windows, Python 3.11–3.13, ruff + pytest |
| D-31 | Names | Product Lucent; import `lucent_ioc`; distribution `lucent-ioc`; CLI `lucent` |
| D-32 | TLD data | Unmodified IANA file; never generated from memory |

---

## B23. Demo (integration test and README example)

`samples/incident_report.txt` (exact content, 8 lines, trailing newline):

```text
Incident ID: DEMO-001
Observed address: 203.0.113.10
Reported host: example[.]com
Reported URL: hxxps://example[.]com/test?id=42
SHA256: aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
Attachment: invoice.zip
Contact: analyst@example.org
Repeated address: 203.0.113.10
```

Command:

```bash
lucent scan samples/incident_report.txt --output -
```

Expected JSON (only `timestamp_utc` and `tld_snapshot` may differ; `tool.version` matches the installed version):

```json
{
  "schema_version": "1.0",
  "tool": {"name": "Lucent", "version": "1.0.0"},
  "scan": {
    "timestamp_utc": "2026-10-28T12:00:00Z",
    "input": "incident_report.txt",
    "recursive": false,
    "strict": false,
    "allow_ambiguous_tlds": false,
    "status": "completed",
    "files": {"discovered": 1, "processed": 1, "skipped": 0, "failed": 0},
    "limits": {"max_file_size_bytes": 52428800, "max_files": 10000, "max_sources_per_ioc": 100},
    "tld_snapshot": "<from tlds.txt header>"
  },
  "summary": {
    "total_unique_iocs": 4,
    "by_type": {"ipv4": 1, "domain": 1, "url": 1, "md5": 0, "sha1": 0, "sha256": 1},
    "rejected_candidates": {"total": 1, "by_reason": {"ambiguous_file_extension_tld": 1}}
  },
  "iocs": [
    {
      "type": "ipv4",
      "value": "203.0.113.10",
      "validation_status": "valid_syntax",
      "occurrences": 2,
      "source_count": 2,
      "sources_truncated": false,
      "original_values": ["203.0.113.10"],
      "original_values_truncated": false,
      "sources": [
        {"file": "incident_report.txt", "line": 2},
        {"file": "incident_report.txt", "line": 8}
      ]
    },
    {
      "type": "domain",
      "value": "example.com",
      "validation_status": "valid_syntax",
      "occurrences": 2,
      "source_count": 2,
      "sources_truncated": false,
      "original_values": ["example[.]com"],
      "original_values_truncated": false,
      "sources": [
        {"file": "incident_report.txt", "line": 3},
        {"file": "incident_report.txt", "line": 4, "via": "url_host"}
      ]
    },
    {
      "type": "url",
      "value": "https://example.com/test?id=42",
      "validation_status": "valid_syntax",
      "occurrences": 1,
      "source_count": 1,
      "sources_truncated": false,
      "original_values": ["hxxps://example[.]com/test?id=42"],
      "original_values_truncated": false,
      "sources": [{"file": "incident_report.txt", "line": 4}]
    },
    {
      "type": "sha256",
      "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "validation_status": "valid_syntax",
      "occurrences": 1,
      "source_count": 1,
      "sources_truncated": false,
      "original_values": ["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"],
      "original_values_truncated": false,
      "sources": [{"file": "incident_report.txt", "line": 5}]
    }
  ],
  "warnings": [],
  "errors": []
}
```

The JSON above is shown compacted for readability; actual output uses `indent=2`. The test compares parsed JSON, not text. Exit code must be 0. stdout must contain only the JSON.

Why each result holds: line 2 and 8 IP → one record, 2 occurrences; line 3 bare defanged domain; line 4 URL normalized and its host derived; line 5 hash; line 6 `invoice.zip` rejected (ambiguous TLD, bare, not defanged); line 7 email masked; "DEMO-001", "SHA256:" and labels produce nothing.

---

## B24. Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `lucent` not found | Not installed in active venv | Activate `.venv`; `pip install -e ".[dev]"` |
| `lucent scan` unknown command | Typer single-command collapse | Add `@app.callback()` |
| TLD file missing at runtime | Not in wheel or not obtained | Check §B6.2.1 and wheel contents |
| Filenames reported as domains | TLD check bypassed | Test `report.pdf` against validator |
| `other.com` missing from URL path | Expected (masking) | None |
| Duplicates remain | Key built before canonicalization | Canonicalize first |
| JSON/CSV disagree | Exporters rebuild data | Serialize from one Report |
| Windows path mismatch | Backslashes | `as_posix()` |
| Flaky snapshots | Unfrozen clock/unsorted sets | Inject clock; sort |
| Tests can't read stderr | Click version difference | §B14.3 |

---

## B25. Final reminders for the builder

1. **Never run Git write commands or anything touching GitHub. Give the user the commands.** (Part A, A1)
2. Never fabricate results, outputs, or the TLD list.
3. Stop after every milestone with the full report and Git handoff block.
4. Ask when something contradicts this document or would change a contract.
5. Tier 1 first; Tier 2 only with time and user agreement; Tier 3 never in v1.

## B26. Final definition

Lucent is a small, offline tool that turns unstructured and semi-structured incident text into validated, normalized, deduplicated and traceable potential IOCs. Its quality is measured by predictable schemas, reliable provenance, visible rejections, controlled normalization, clear failure handling, reproducible output and honesty about what syntax validation proves. It never confuses an indicator's format with its threat status.

## Clarifications

All recorded 2026-10-28 during the v1.0.0 build. None changes a contract (CLI, report schema, defang set, validation rules or exit codes).

1. **File-count limit scope (§B4.7).** `--max-files` counts files that would otherwise be read (supported extension, not a symlink), in sorted order. It is applied before the size check, so a file beyond the limit is skipped for the limit even if it is also over-size. The single `file_limit_reached` warning uses the relative path of the first file skipped by the limit.
2. **Symlinked directories (§B4.6).** The `symlink_skipped` warning for a symlinked directory is emitted only in `--recursive` scans (a non-recursive scan never enters any subdirectory). Symlinked directories whose name starts with `.` are ignored silently, like other dot-directories. On Windows, directory junctions are treated as symlinks.
3. **Decode fallback (§B4.2).** Each file is first checked with a streaming strict UTF-8 (BOM-aware) decoder. If that fails, the file is read once with `errors="replace"` and the `decode_replacement` warning is added. This gives the same result as "re-read on error" without duplicating segments already yielded.
4. **JSON quoted keys (§B4.4).** `["key"]` uses `json.dumps(key, ensure_ascii=False)`, so non-ASCII keys stay readable.
5. **CSV field size limit (§B4.3).** `csv.field_size_limit` is set to `min(max_file_size_bytes, 2**31 - 1)` because the C `long` is 32-bit on Windows. Empty CSV cells are not scanned (no observable effect).
6. **URL length (§B6.3).** The 2,048-character check is applied to the normalized URL, the value the validation table operates on.
7. **Derived host source.** A valid URL's host is validated as a URL host (ambiguous-TLD rule off). Its `original_value` is the host as written in the raw authority, excluding userinfo and port.
8. **Path conflicts (§B12.1).** Directory scans exclude the resolved `--output` file and everything under `--output-dir` from discovery, so an output target can only collide with an input when INPUT is a single file; that case is checked before scanning and exits 1 even with `--force`. A pre-existing file inside a scanned directory that is named as `--output` is treated as an output (overwritten only with `--force`), not as an input.
9. **Existing-output check order.** The path-conflict and existing-output checks run before the scan, so nothing is read or written when they fail.
10. **Usage errors (§B10.3).** Typer 0.27 bundles its own Click copy (`typer._click`) and exposes `typer.BadParameter` publicly; usage errors are raised with it (exit 2).
11. **Unexpected per-file exceptions.** Any exception other than the reader's own read/parse failures is recorded as an `ErrorEntry` with `stage: "read"`, the exception class name as `error_type`, and a generic message, so a single file can never abort the scan.
12. **Warning order.** Discovery warnings come first (symlinked directories, then per-file warnings in sorted path order), followed by read-time warnings (`decode_replacement`, `jsonl_line_invalid`) in processing order.
13. **CSV line endings.** `csv.writer`'s default `\r\n` record terminator is used (RFC 4180), on every OS.
14. **Terminal output.** The IOC table is shown only when there is no destination. Its value column wraps instead of truncating, so full values can be copied. Output paths are printed as the user gave them.
15. **`--verbose` hook.** `run_scan` accepts an optional keyword `on_file(rel_path, exc)` callback, called after each file is read. The CLI uses it to print `Processed: <file>` / `Failed: <file>` lines and, for failures, the full traceback. The pipeline itself still never prints.
16. **`--quiet` (§B10.4).** Prints per-file error lines from the report and the final `Status:` line. Fatal errors and export failures are always printed to stderr.
17. **JSONL invalid lines (§B4.5).** Lines that fail `json.loads` (including excessive nesting) add one `jsonl_line_invalid` warning each, with the 1-based line number in the message.
18. **Styled terminal output (§B10.4), added after v1.0.0 build review.** The human-readable output is styled by `ui.py` (banner, rules, stat cards, type bars, coloured table). It still contains every §B10.4 item, with each warning and error on one line and the same `Label: value` text, and is still written to stderr with `--output -`. `--quiet` prints no banner and keeps its exact lines. A bare `lucent` shows a welcome screen and exits 0 (previously help with exit 2). Colour follows Rich's terminal detection and `NO_COLOR`.
