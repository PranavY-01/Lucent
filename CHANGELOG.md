# Changelog

All notable changes to this project are documented here.
The format follows Keep a Changelog, and this project uses Semantic Versioning.

## [Unreleased]

## [1.0.0] - 2026-10-28

### Added
- Project skeleton: `pyproject.toml`, `lucent` console entry point, `python -m lucent_ioc`, `--version`.
- Pydantic report models with invariant validation (`models.py`) and static configuration (`config.py`).
- `docs/SPEC.md`, `docs/architecture.md`, CI workflow (Ubuntu and Windows, Python 3.11 to 3.13), network-guard test fixture.
- File discovery with symlink, hidden-directory, unsupported-extension, size and file-count rules.
- Readers for `.txt`, `.log`, `.md` (line provenance), `.csv` (record and column), `.json` (JSON path), with UTF-8/BOM handling and a `decode_replacement` fallback.
- `.jsonl` / `.ndjson` input with line and JSON-path provenance and `jsonl_line_invalid` warnings.
- Synthetic sample inputs under `samples/`.
- Defang-aware detectors for IPv4, domains, HTTP/HTTPS URLs, MD5, SHA-1 and SHA-256 on raw text, with URL trailing-punctuation trimming and URL/email span masking.
- Normalization of the documented defang forms (scheme, separator and URL authority only).
- Syntax validation with rejection reasons, bundled IANA TLD list (snapshot `2026102800`), ambiguous-TLD rule, and URL-host derivation.
- `scripts/update_tlds.py` developer tool to refresh the TLD list.
- Deduplication by type and canonical value with merged sources, occurrence counts and source/original-value caps.
- Report building with invariant checks, scan status, and rejected-candidate counts by reason.
- JSON and CSV exporters (CSV formula guard, atomic writes), `--output FILE`, `--output -` (stdout) and `--output-dir`.
- `lucent scan` command with `--recursive`, `--format`, `--force`, `--strict`, `--max-file-size`, `--max-files`, `--max-sources-per-ioc`, `--allow-ambiguous-tlds`, `--verbose`, `--quiet`, terminal summary and exit codes 0/1/2/3.
- Styled terminal interface (`ui.py`): bold ASCII `LUCENT` banner with a green-yellow-orange-red gradient on the welcome screen, `--help` and scans; gradient section rules; big-number stat cards; IOC-by-type bars; coloured IOC table, warnings, errors and status; live scanning spinner on interactive terminals. Typer's help and error panels use the same palette. Colour is dropped when output is not a terminal or `NO_COLOR` is set, and box, bar and spinner characters fall back to ASCII on non-UTF-8 consoles.
- Welcome screen for a bare `lucent` (exit code 0).
- Unit, golden, CLI, UI, integration, determinism and demo tests.

[Unreleased]: https://github.com/PranavY-01/Lucent/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/PranavY-01/Lucent/releases/tag/v1.0.0
