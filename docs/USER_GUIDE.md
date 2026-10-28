# Lucent User Guide

For Lucent **1.0.0**.

Lucent is an offline command-line tool. It reads local text files (reports, logs, CSV and JSON exports), extracts **potential** Indicators of Compromise (IOCs), validates their syntax, removes duplicates, and records exactly where each one was found.

---

## Contents

1. [About this guide](#1-about-this-guide)
2. [What Lucent is and is not](#2-what-lucent-is-and-is-not)
3. [Glossary](#3-glossary)
4. [Cheat sheet](#4-cheat-sheet)
5. [Install](#5-install)
6. [Quick start](#6-quick-start)
7. [Understanding the report](#7-understanding-the-report)
8. [Command reference](#8-command-reference)
9. [Choosing where output goes](#9-choosing-where-output-goes)
10. [Input formats and provenance](#10-input-formats-and-provenance)
11. [Scanning folders and limits](#11-scanning-folders-and-limits)
12. [Working with CSV output](#12-working-with-csv-output)
13. [Defanged indicators](#13-defanged-indicators)
14. [Rejected candidates](#14-rejected-candidates)
15. [Warnings, errors and scan status](#15-warnings-errors-and-scan-status)
16. [Exit codes and `--strict`](#16-exit-codes-and---strict)
17. [Recipes](#17-recipes)
18. [Troubleshooting](#18-troubleshooting)
19. [Known limitations](#19-known-limitations)

---

## 1. About this guide

**Who it is for.** Analysts and students who want to run Lucent on their own files, and anyone who wants a quick look at what it does. If you only want to see it working, read sections 4 to 6.

**Conventions.**

- Run every command from the root of the Lucent repository (the folder that contains `samples/`).
- `PS>` marks Windows PowerShell. `$` marks a POSIX shell (bash or zsh on Linux and macOS, or Git Bash on Windows). When a command is the same in both, it is shown once without a prompt.
- Some sections ask you to create small practice files in `demo/`, `helpers/` and `big/`. They contain only synthetic data. Delete these folders when you are done. Reports go into `reports/`, which Git already ignores.

**How the output was captured.** Every output in this guide was produced by running the command against Lucent 1.0.0 on Windows 11 with Python 3.12. Expect these differences on your machine:

- `timestamp_utc` in reports is the time of your run.
- Table borders may look different (some terminals draw them with `+`, `-` and `|`), and column widths follow your terminal width.
- On Windows, Lucent prints output paths with backslashes, for example `reports\lucent_iocs.json`.
- The Linux and macOS commands are the standard equivalents; they were run in Git Bash on Windows, not on Linux or macOS.

---

## 2. What Lucent is and is not

**Lucent does:**

- Read `.txt`, `.log`, `.md`, `.csv`, `.json`, `.jsonl` and `.ndjson` files, one file or a whole folder.
- Extract potential IOCs of six types: `ipv4`, `domain`, `url` (HTTP and HTTPS), `md5`, `sha1`, `sha256`.
- Undo common "defanging" such as `example[.]com` or `hxxps://`, while keeping the original text.
- Validate syntax (for example, that an IP address is in range and a domain ends in a real top-level domain).
- Merge duplicates and keep every place each indicator was seen.
- Write a JSON or CSV report, and count the candidates it rejected and why.

**Lucent does not:**

- Decide whether anything is malicious, safe or suspicious. Every reported IOC has `"validation_status": "valid_syntax"`, which only means the text has the right shape. A valid IP address may be private or harmless; a valid domain may be perfectly legitimate.
- Make network calls. There is no DNS lookup, no HTTP request, no reputation or threat-intelligence check.
- Execute, open or "detonate" anything. Input is treated as plain text.
- Extract IPv6 addresses, email addresses or Unicode (non-ASCII) domain names.
- Parse timestamps, build timelines, hash files, or export STIX.

**Safety and privacy behaviour:**

- Lucent never overwrites a file you are scanning, and refuses to overwrite an existing report unless you add `--force` (section 9).
- Reports are written to a temporary file first and then renamed into place, so a failed write does not leave a half-written report.
- Reports and messages use relative paths and never quote the lines of your input files.
- Practice data in this guide uses only reserved names (`example.com`, `example.org`, `example.net`) and documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`).

---

## 3. Glossary

| Term | Meaning |
|---|---|
| **IOC** | Indicator of Compromise: an artefact such as an IP address, domain, URL or file hash that may point to malicious activity. Lucent extracts *potential* IOCs only. |
| **Candidate** | A piece of text that looks like an IOC before validation. |
| **Rejected candidate** | A candidate that failed validation. Lucent counts it by reason but does not list it. |
| **`valid_syntax`** | The only validation status Lucent assigns. It means "well-formed", not "malicious". |
| **Defanged** | Deliberately altered to prevent accidental clicks, for example `example[.]com` or `hxxps://`. |
| **Canonical value** | The normalized form Lucent reports: defanging removed, lowercased where appropriate. Shown as `value`. |
| **Original value** | The text exactly as it appeared in your file. Shown in `original_values`. |
| **Source** | One place an IOC was found: a file plus a line number, a CSV record and column, or a JSON path. |
| **Provenance** | The list of sources for an IOC. |
| **Occurrence** | One sighting. The same IOC twice on one line is 2 occurrences but 1 source. |
| **Derived IOC** | A domain or IPv4 address taken from the host part of a valid URL. Its source carries `"via": "url_host"`. |
| **TLD** | Top-level domain, the last label of a domain (`com`, `org`, `zip`). Lucent checks it against a bundled copy of the IANA list. |
| **Ambiguous TLD** | A real TLD that is also a common file extension (`zip`, `mov`, `sh`, `py`, `pl`, `rs`, `md`, `ps`, `so`, `cab`, `one`). |
| **Scan status** | `completed`, `completed_with_warnings` or `partial` (section 15). |
| **Segment** | The unit Lucent scans: a line of a text file, a CSV cell, or a JSON string value. |

---

## 4. Cheat sheet

**Common commands**

| Task | Command |
|---|---|
| Check the installed version | `lucent --version` |
| Summary and table in the terminal | `lucent scan samples/incident_report.txt` |
| JSON report to a file | `lucent scan samples/incident_report.txt --output reports/incident.json` |
| JSON report to the screen or a pipe | `lucent scan samples/incident_report.txt --output -` |
| CSV report to a file | `lucent scan samples/incident_report.txt --format csv --output reports/incident.csv` |
| Whole folder, both formats | `lucent scan samples/ --recursive --format both --output-dir reports/` |
| Replace an existing report | add `--force` |
| Only errors and the final status | add `--quiet` |
| List each file as it is read | add `--verbose` |
| Treat warnings as failure (exit 3) | add `--strict` |
| Same as `lucent` without the launcher | `python -m lucent_ioc scan ...` |

**Where output goes**

| You give | Lucent writes |
|---|---|
| no `--output` / `--output-dir` | Summary and table in the terminal only (JSON format only) |
| `--output FILE` | One report (JSON or CSV) to `FILE` |
| `--output -` | One report to standard output; the summary goes to standard error |
| `--output-dir DIR` | `DIR/lucent_iocs.json` and/or `DIR/lucent_iocs.csv` (required for `--format both`) |

**Exit codes**

| Code | Meaning |
|---|---|
| `0` | Finished (`completed` or `completed_with_warnings`). Zero IOCs is still 0. |
| `1` | Could not run or could not write: bad input, nothing processed, report already exists, output would overwrite the input. |
| `2` | Invalid or conflicting options. |
| `3` | `partial` (a file failed), or `--strict` with any warning. |

---

## 5. Install

You need **Python 3.11 or newer**. Lucent has three runtime dependencies (Typer, Rich and Pydantic), which `pip` installs for you.

1. Get the code and enter the folder:

   ```bash
   git clone https://github.com/PranavY-01/Lucent.git
   cd Lucent
   ```

2. Create a virtual environment:

   ```bash
   python -m venv .venv
   ```

3. Activate it:

   ```powershell
   PS> .venv\Scripts\Activate.ps1
   ```

   ```bash
   $ source .venv/bin/activate        # Linux and macOS
   $ source .venv/Scripts/activate    # Git Bash on Windows
   ```

4. Install Lucent. Use the first line if you also want to run the test suite; the second installs Lucent alone:

   ```bash
   python -m pip install -e ".[dev]"
   python -m pip install .
   ```

5. Check it works:

   ```
   lucent --version
   ```

   ```text
   lucent 1.0.0
   ```

   The module form gives the same result:

   ```
   python -m lucent_ioc --version
   ```

   ```text
   lucent 1.0.0
   ```

Activate the virtual environment again (step 3) each time you open a new terminal.

---

## 6. Quick start

The repository ships with synthetic samples. `samples/incident_report.txt` contains:

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

**Step 1: see what Lucent finds.**

```
lucent scan samples/incident_report.txt
```

```text
Input: incident_report.txt
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 4 unique (ipv4 1, domain 1, url 1, md5 0, sha1 0, sha256 1)
Rejected candidates: 1 (ambiguous_file_extension_tld 1)
┌────────┬─────────────┬─────────┬────────────────────────────────────────────┐
│ type   │ occurrences │ sources │ value                                      │
├────────┼─────────────┼─────────┼────────────────────────────────────────────┤
│ ipv4   │ 2           │ 2       │ 203.0.113.10                               │
│ domain │ 2           │ 2       │ example.com                                │
│ url    │ 1           │ 1       │ https://example.com/test?id=42             │
│ sha256 │ 1           │ 1       │ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa │
│        │             │         │ aaaaaaaaaaaaaaaaaaaaaa                     │
└────────┴─────────────┴─────────┴────────────────────────────────────────────┘
Status: completed
```

Nothing is written to disk. Note what happened:

- The IP on lines 2 and 8 is reported once, with 2 occurrences.
- `example[.]com` and `hxxps://example[.]com/...` were defanged; Lucent reports them as `example.com` and `https://example.com/test?id=42`.
- `invoice.zip` was rejected: `.zip` is a real TLD but is far more likely a file name here (section 14).
- The email address was ignored on purpose.

**Step 2: get the full report as JSON.**

```
lucent scan samples/incident_report.txt --output -
```

The JSON report goes to standard output and the summary to standard error, so you see both. The full report is shown and explained in [section 7](#7-understanding-the-report).

**Step 3: scan a whole folder into report files.**

```
lucent scan samples/ --recursive --format both --output-dir reports/
```

```text
Input: samples
Files: discovered 4, processed 4, skipped 0, failed 0
IOCs: 30 unique (ipv4 8, domain 11, url 7, md5 1, sha1 1, sha256 2)
Rejected candidates: 5 (ambiguous_file_extension_tld 1, invalid_ipv4 1, unknown_tld 3)
Output: reports\lucent_iocs.json
Output: reports\lucent_iocs.csv
Status: completed
```

You now have `reports/lucent_iocs.json` and `reports/lucent_iocs.csv`.

---

## 7. Understanding the report

This is the complete JSON report for `samples/incident_report.txt` (from `lucent scan samples/incident_report.txt --output -`):

```json
{
  "schema_version": "1.0",
  "tool": {
    "name": "Lucent",
    "version": "1.0.0"
  },
  "scan": {
    "timestamp_utc": "2026-10-28T15:50:05Z",
    "input": "incident_report.txt",
    "recursive": false,
    "strict": false,
    "allow_ambiguous_tlds": false,
    "status": "completed",
    "files": {
      "discovered": 1,
      "processed": 1,
      "skipped": 0,
      "failed": 0
    },
    "limits": {
      "max_file_size_bytes": 52428800,
      "max_files": 10000,
      "max_sources_per_ioc": 100
    },
    "tld_snapshot": "2026102800"
  },
  "summary": {
    "total_unique_iocs": 4,
    "by_type": {
      "ipv4": 1,
      "domain": 1,
      "url": 1,
      "md5": 0,
      "sha1": 0,
      "sha256": 1
    },
    "rejected_candidates": {
      "total": 1,
      "by_reason": {
        "ambiguous_file_extension_tld": 1
      }
    }
  },
  "iocs": [
    {
      "type": "ipv4",
      "value": "203.0.113.10",
      "validation_status": "valid_syntax",
      "occurrences": 2,
      "source_count": 2,
      "sources_truncated": false,
      "original_values": [
        "203.0.113.10"
      ],
      "original_values_truncated": false,
      "sources": [
        {
          "file": "incident_report.txt",
          "line": 2
        },
        {
          "file": "incident_report.txt",
          "line": 8
        }
      ]
    },
    {
      "type": "domain",
      "value": "example.com",
      "validation_status": "valid_syntax",
      "occurrences": 2,
      "source_count": 2,
      "sources_truncated": false,
      "original_values": [
        "example[.]com"
      ],
      "original_values_truncated": false,
      "sources": [
        {
          "file": "incident_report.txt",
          "line": 3
        },
        {
          "file": "incident_report.txt",
          "line": 4,
          "via": "url_host"
        }
      ]
    },
    {
      "type": "url",
      "value": "https://example.com/test?id=42",
      "validation_status": "valid_syntax",
      "occurrences": 1,
      "source_count": 1,
      "sources_truncated": false,
      "original_values": [
        "hxxps://example[.]com/test?id=42"
      ],
      "original_values_truncated": false,
      "sources": [
        {
          "file": "incident_report.txt",
          "line": 4
        }
      ]
    },
    {
      "type": "sha256",
      "value": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
      "validation_status": "valid_syntax",
      "occurrences": 1,
      "source_count": 1,
      "sources_truncated": false,
      "original_values": [
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
      ],
      "original_values_truncated": false,
      "sources": [
        {
          "file": "incident_report.txt",
          "line": 5
        }
      ]
    }
  ],
  "warnings": [],
  "errors": []
}
```

### Top level

| Key | Meaning |
|---|---|
| `schema_version` | Version of the report format (`"1.0"`). It changes independently of the tool version. |
| `tool` | Tool name and version that produced the report. |
| `scan` | How the scan was run and how it ended. |
| `summary` | Counts. |
| `iocs` | The unique indicators, sorted by type (`ipv4`, `domain`, `url`, `md5`, `sha1`, `sha256`) and then by value. |
| `warnings` | Things that did not stop the scan, such as a skipped file (section 15). |
| `errors` | Files that could not be read or parsed (section 15). |

### `scan`

| Key | Meaning |
|---|---|
| `timestamp_utc` | When the scan ran, in UTC, to the second. |
| `input` | The name of the file or folder you scanned. Never a full path. |
| `recursive`, `strict`, `allow_ambiguous_tlds` | Whether those options were used. |
| `status` | `completed`, `completed_with_warnings` or `partial`. |
| `files` | `discovered` = `processed` + `skipped` + `failed`. |
| `limits` | The limits in force. `max_file_size_bytes` is `--max-file-size` converted to bytes. |
| `tld_snapshot` | Version of the bundled IANA top-level-domain list used for validation. |

### `summary`

| Key | Meaning |
|---|---|
| `total_unique_iocs` | Number of entries in `iocs`. |
| `by_type` | Count per type. All six types are always listed, including zeros. |
| `rejected_candidates.total` | How many candidates failed validation, counting every occurrence. |
| `rejected_candidates.by_reason` | The same total split by reason (section 14). Empty `{}` when nothing was rejected. |

### Each entry in `iocs`

| Key | Meaning |
|---|---|
| `type` | `ipv4`, `domain`, `url`, `md5`, `sha1` or `sha256`. |
| `value` | The canonical value. Use this for searching and comparing. |
| `validation_status` | Always `valid_syntax`. |
| `occurrences` | Total sightings, including repeats on the same line. |
| `source_count` | Number of distinct places it was found. |
| `sources` | Those places, sorted. At most `--max-sources-per-ioc` entries (default 100). |
| `sources_truncated` | `true` if `sources` was cut short; `source_count` still has the full number. |
| `original_values` | Each distinct way it was written in your files, sorted. At most 20. |
| `original_values_truncated` | `true` if more than 20 distinct forms were seen. |

So for one IOC, `occurrences` ≥ `source_count` ≥ number of entries in `sources` ≥ 1.

### Each source

A source always has `file`. When you scan a folder, `file` is the path relative to that folder, always written with `/`. The other keys appear only when they apply; Lucent never writes `null`:

| Key | Present for |
|---|---|
| `line` | `.txt`, `.log`, `.md`, `.jsonl`, `.ndjson` (1-based) |
| `record`, `column` | `.csv` |
| `path` | `.json`, `.jsonl`, `.ndjson` |
| `via` | `"url_host"` when the IOC was taken from a URL's host |

In the example, `example.com` has two sources: line 3, where it appears on its own, and line 4 with `"via": "url_host"`, because it is the host of the URL on that line.

---

## 8. Command reference

Lucent has one command, `scan`.

```
lucent --help
```

```text
                                                                               
 Usage: lucent [OPTIONS] COMMAND [ARGS]...                                     
                                                                               
 Offline extraction of potential IOCs from reports and logs.                   
                                                                               
┌─ Options ───────────────────────────────────────────────────────────────────┐
│ --version          Show the version and exit.                               │
│ --help             Show this message and exit.                              │
└─────────────────────────────────────────────────────────────────────────────┘
┌─ Commands ──────────────────────────────────────────────────────────────────┐
│ scan  Scan INPUT for potential IOCs.                                        │
└─────────────────────────────────────────────────────────────────────────────┘
```

```
lucent scan --help
```

```text
                                                                               
 Usage: lucent scan [OPTIONS] {INPUT}                                          
                                                                               
 Scan INPUT for potential IOCs.                                                
                                                                               
┌─ Arguments ─────────────────────────────────────────────────────────────────┐
│ *    INPUT      <path>  File or directory to scan. [required]               │
└─────────────────────────────────────────────────────────────────────────────┘
┌─ Options ───────────────────────────────────────────────────────────────────┐
│ --recursive                                    Descend into subdirectories. │
│ --format                      <json|csv|both>  Output format: json          │
│                                                (default), csv or both.      │
│ --output                      FILE             Write one format to FILE, or │
│                                                '-' for stdout.              │
│ --output-dir                  DIR              Write lucent_iocs.json /     │
│                                                lucent_iocs.csv here.        │
│ --force                                        Overwrite existing output    │
│                                                files.                       │
│ --strict                                       Exit 3 if the scan produced  │
│                                                any warning.                 │
│ --max-file-size               MB [x>=1]        Per-file size limit in MB.   │
│                                                [default: 50]                │
│ --max-files                   N [x>=1]         Maximum files per scan.      │
│                                                [default: 10000]             │
│ --max-sources-per-ioc         N [x>=1]         Sources stored per IOC.      │
│                                                [default: 100]               │
│ --allow-ambiguous-tlds                         Accept bare domains whose    │
│                                                TLD is also a file extension │
│                                                (e.g. .zip).                 │
│ --verbose                                      Show each file and full      │
│                                                per-file tracebacks.         │
│ --quiet                                        Show only errors and the     │
│                                                final status.                │
│ --help                                         Show this message and exit.  │
└─────────────────────────────────────────────────────────────────────────────┘
```

| Option | Default | What it does | More |
|---|---|---|---|
| `INPUT` | required | A file or a folder. | §10, §11 |
| `--recursive` | off | Also scan subfolders. Without it, only the files directly inside the folder are scanned. | §11 |
| `--format json\|csv\|both` | `json` | Report format. `csv` needs `--output` or `--output-dir`; `both` needs `--output-dir`. | §9, §12 |
| `--output FILE` | none | Write one report to `FILE`. Use `-` for standard output. Missing parent folders are created. | §9 |
| `--output-dir DIR` | none | Write `lucent_iocs.json` and/or `lucent_iocs.csv` into `DIR` (created if missing). | §9 |
| `--force` | off | Allow replacing existing report files. Never allows overwriting the input. | §9 |
| `--strict` | off | Exit with code 3 if the scan produced any warning. Does not change the report. | §16 |
| `--max-file-size MB` | `50` | Skip files larger than this (whole megabytes, at least 1). | §11 |
| `--max-files N` | `10000` | Read at most N files; the rest are skipped. | §11 |
| `--max-sources-per-ioc N` | `100` | Keep at most N sources per IOC in the report. | §17 |
| `--allow-ambiguous-tlds` | off | Accept bare domains such as `invoice.zip`. | §14 |
| `--verbose` | off | Print one line per file read, and a full Python traceback for files that fail. | §17 |
| `--quiet` | off | Print only per-file errors and the final status line. Cannot be combined with `--verbose`. | §15 |

---

## 9. Choosing where output goes

### Terminal only (default)

With no `--output` or `--output-dir`, Lucent prints the summary and a table of IOCs and writes nothing. The table shows at most 50 rows and then prints `showing 50 of N`. This mode is JSON-only, so `--format csv` and `--format both` need a destination.

### A single report file: `--output FILE`

```
lucent scan samples/incident_report.txt --output reports/incident.json
```

```text
Input: incident_report.txt
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 4 unique (ipv4 1, domain 1, url 1, md5 0, sha1 0, sha256 1)
Rejected candidates: 1 (ambiguous_file_extension_tld 1)
Output: reports\incident.json
Status: completed
```

Use `--format csv` to write CSV instead.

### Standard output: `--output -`

The report goes to standard output and the human-readable summary goes to standard error. This lets you pipe the report into another program:

```
lucent scan samples/incident_report.txt --format csv --output -
```

Standard output contains only the CSV:

```text
type,value,validation_status,occurrences,source_count,original_values,sources
ipv4,203.0.113.10,valid_syntax,2,2,"[""203.0.113.10""]","[{""file"":""incident_report.txt"",""line"":2},{""file"":""incident_report.txt"",""line"":8}]"
domain,example.com,valid_syntax,2,2,"[""example[.]com""]","[{""file"":""incident_report.txt"",""line"":3},{""file"":""incident_report.txt"",""line"":4,""via"":""url_host""}]"
url,https://example.com/test?id=42,valid_syntax,1,1,"[""hxxps://example[.]com/test?id=42""]","[{""file"":""incident_report.txt"",""line"":4}]"
sha256,aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa,valid_syntax,1,1,"[""aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa""]","[{""file"":""incident_report.txt"",""line"":5}]"
```

> **Windows PowerShell:** to save a report to a file, use `--output FILE` rather than redirecting `--output -` with `>`. When PowerShell pipes or redirects a program's output it re-encodes the text, and in testing it added a byte-order mark that made Python's `json.load` reject the result. Bash and other POSIX shells pass the bytes through unchanged.

### A report folder: `--output-dir DIR`

Lucent writes `lucent_iocs.json`, `lucent_iocs.csv`, or both (`--format both`) into `DIR`, creating it if needed. See Quick start step 3 for the output.

### Existing reports and `--force`

Lucent refuses to replace a report that already exists, and checks this before reading anything:

```
lucent scan samples/ --recursive --format both --output-dir reports/
```

```text
Error: output file reports\lucent_iocs.json already exists (use --force to overwrite)
```

Exit code: `1`. Add `--force` to replace it:

```
lucent scan samples/ --recursive --format both --output-dir reports/ --force
```

```text
Input: samples
Files: discovered 4, processed 4, skipped 0, failed 0
IOCs: 30 unique (ipv4 8, domain 11, url 7, md5 1, sha1 1, sha256 2)
Rejected candidates: 5 (ambiguous_file_extension_tld 1, invalid_ipv4 1, unknown_tld 3)
Output: reports\lucent_iocs.json
Output: reports\lucent_iocs.csv
Status: completed
```

### Lucent never overwrites the file it is scanning

Even with `--force`:

```
lucent scan samples/incident_report.txt --output samples/incident_report.txt --force
```

```text
Error: output path samples\incident_report.txt is the input file
```

Exit code: `1`. The input file is untouched.

When you scan a folder, Lucent skips its own output: the `--output` file and everything inside `--output-dir` are left out of the scan, even if they sit inside the folder you are scanning.

### Option combinations that are not allowed

These stop with exit code `2` before anything is read:

```
lucent scan samples/incident_report.txt --format csv
```

```text
Usage: lucent scan [OPTIONS] {INPUT}
Try 'lucent scan --help' for help.
┌─ Error ─────────────────────────────────────────────────────────────────────┐
│ Invalid value: --format csv requires --output or --output-dir.              │
└─────────────────────────────────────────────────────────────────────────────┘
```

The other messages, from `--format both` without `--output-dir`, and from `--output` together with `--output-dir`:

```text
│ Invalid value: --format both requires --output-dir.                         │
│ Invalid value: --output and --output-dir cannot be used together.           │
```

`--verbose` with `--quiet`, and a value below 1 for `--max-file-size`, `--max-files` or `--max-sources-per-ioc`, are rejected the same way.

---

## 10. Input formats and provenance

File types are recognised by extension, ignoring case (`.TXT` works). Text is read as UTF-8; a UTF-8 byte-order mark at the start of a file is ignored.

| Extensions | What Lucent scans | Source fields |
|---|---|---|
| `.txt`, `.log`, `.md` | Each line | `line` |
| `.csv` | Each cell, including the header row | `record`, `column` |
| `.json` | Every string value (not keys, numbers, booleans or null) | `path` |
| `.jsonl`, `.ndjson` | Every string value of each line's JSON document | `line`, `path` |

### Text files (`.txt`, `.log`, `.md`)

Create `demo/notes.md`:

```markdown
# Case notes

- Phishing host: login.example[.]net
- Callback IP: 198.51.100.17
- Payload link: https://cdn.example.org/files/setup.zip
```

```
lucent scan demo/notes.md
```

```text
Input: notes.md
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 4 unique (ipv4 1, domain 2, url 1, md5 0, sha1 0, sha256 0)
Rejected candidates: 0
┌────────┬─────────────┬─────────┬─────────────────────────────────────────┐
│ type   │ occurrences │ sources │ value                                   │
├────────┼─────────────┼─────────┼─────────────────────────────────────────┤
│ ipv4   │ 1           │ 1       │ 198.51.100.17                           │
│ domain │ 1           │ 1       │ cdn.example.org                         │
│ domain │ 1           │ 1       │ login.example.net                       │
│ url    │ 1           │ 1       │ https://cdn.example.org/files/setup.zip │
└────────┴─────────────┴─────────┴─────────────────────────────────────────┘
Status: completed
```

In the JSON report (`--output -`), the defanged host keeps its original form and its line number:

```json
{
  "type": "domain",
  "value": "login.example.net",
  "validation_status": "valid_syntax",
  "occurrences": 1,
  "source_count": 1,
  "sources_truncated": false,
  "original_values": [
    "login.example[.]net"
  ],
  "original_values_truncated": false,
  "sources": [
    {
      "file": "notes.md",
      "line": 3
    }
  ]
}
```

`cdn.example.org` only appears inside the URL on line 5, so its source is `{"file": "notes.md", "line": 5, "via": "url_host"}`. `setup.zip` in the URL path is not reported separately (see §19).

### CSV files

The first row is the header and supplies the column names. It is also scanned, as `record: 1`. Records count CSV rows, not physical lines: a quoted cell that spans two lines is still one record. Cells beyond the header's width, or under an empty header cell, are named `col_<n>` (1-based).

In `samples/sample_iocs.csv`, the third record has a multi-line note. Sources from `lucent scan samples/sample_iocs.csv --output -`:

```json
[{"file": "sample_iocs.csv", "record": 3, "column": "indicator"}]
```

for `evil-portal.example.com`, and for `example.org`, which comes from the URL in record 4:

```json
[{"file": "sample_iocs.csv", "record": 4, "column": "indicator", "via": "url_host"}]
```

### JSON files

Every string value is scanned, at any depth. Its location is a JSON path: `$` is the document root, `.name` a key, `["key with spaces"]` a key that is not a simple identifier, and `[0]` an array index. JSON sources have no line number.

From `lucent scan samples/sample_events.json --output -`, the IP in the key `"src ip"` and a domain inside a `tags` array:

```json
[{"file": "sample_events.json", "path": "$.events[0][\"src ip\"]"}]
[{"file": "sample_events.json", "path": "$.events[1].tags[1]", "via": "url_host"}]
```

If a `.json` file is not valid JSON, the whole file fails (an `errors` entry, status `partial`) and contributes nothing. Lucent does not fall back to scanning it as plain text.

### JSON Lines files (`.jsonl`, `.ndjson`)

Each non-blank line is a separate JSON document. Create `demo/events.jsonl`:

```text
{"time": "2026-10-27T10:00:00Z", "msg": "connect to 203.0.113.25"}
{"time": "2026-10-27T10:01:00Z", "tags": ["dns", "c2.example.com"]}
this line is not JSON
```

```
lucent scan demo/events.jsonl --quiet
```

```text
Status: completed_with_warnings
```

Sources carry both the line and the path: `{"file": "events.jsonl", "line": 1, "path": "$.msg"}` and `{"file": "events.jsonl", "line": 2, "path": "$.tags[1]"}`. The bad line is skipped with a warning and the rest of the file is still used:

```json
[
  {
    "code": "jsonl_line_invalid",
    "path": "events.jsonl",
    "message": "events.jsonl: line 3 is not valid JSON, skipped"
  }
]
```

### Files that are not valid UTF-8

Lucent replaces undecodable bytes and carries on, with a warning. To try it, create a file containing a Latin-1 byte:

```
python -c "open('demo/legacy.txt', 'wb').write(b'caf\xe9 host 203.0.113.30\n')"
```

```
lucent scan demo/legacy.txt
```

```text
Input: legacy.txt
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 1 unique (ipv4 1, domain 0, url 0, md5 0, sha1 0, sha256 0)
Rejected candidates: 0
Warning [decode_replacement]: legacy.txt: not valid UTF-8; undecodable bytes replaced
┌──────┬─────────────┬─────────┬──────────────┐
│ type │ occurrences │ sources │ value        │
├──────┼─────────────┼─────────┼──────────────┤
│ ipv4 │ 1           │ 1       │ 203.0.113.30 │
└──────┴─────────────┴─────────┴──────────────┘
Status: completed_with_warnings
```

### Unsupported files

If you name a single file with an unsupported extension, Lucent stops with exit code `1`, for example `Error: unsupported file extension '.toml': pyproject.toml`. Inside a folder, unsupported files are skipped with a warning instead (section 11).

---

## 11. Scanning folders and limits

### What gets scanned

- Without `--recursive`, only files directly inside the folder. With it, subfolders too.
- Folders whose name starts with `.` (such as `.git` or `.venv`) are never entered. Files whose name starts with `.` are scanned normally.
- Files with an unsupported extension are counted as discovered, skipped, and reported with an `unsupported_extension` warning.
- Files are processed in sorted order of their relative path, so repeated runs give the same report.
- Sources use the path relative to the folder you scanned, for example `mixed/malformed.json`.

`tests/fixtures` contains only a subfolder, so a non-recursive scan finds nothing to read:

```
lucent scan tests/fixtures
```

```text
Error: no files were processed
```

Exit code: `1`. With `--recursive`:

```
lucent scan tests/fixtures --recursive --quiet
```

```text
Error [parse] JSONDecodeError: mixed/malformed.json: invalid JSON at line 2
Status: partial
```

Exit code: `3`. That folder contains a deliberately broken file (section 15).

### File-count limit: `--max-files N`

Lucent reads at most N files, in sorted order, and skips the rest with a single warning:

```
lucent scan samples --max-files 2 --output-dir reports/limited
```

```text
Input: samples
Files: discovered 4, processed 2, skipped 2, failed 0
IOCs: 11 unique (ipv4 2, domain 4, url 3, md5 0, sha1 1, sha256 1)
Rejected candidates: 1 (ambiguous_file_extension_tld 1)
Warning [file_limit_reached]: file limit of 2 reached; sample_iocs.csv and later files skipped
Output: reports\limited\lucent_iocs.json
Status: completed_with_warnings
```

### File-size limit: `--max-file-size MB`

Larger files are skipped whole, never cut short. The default is 50 MB. To try it, create a folder with one file over 1 MB and one small file:

```
python -c "import os; os.makedirs('big', exist_ok=True); open('big/big.log', 'w').write('192.0.2.1\n' * 120000); open('big/small.txt', 'w').write('198.51.100.9\n')"
```

```
lucent scan big --max-file-size 1 --output-dir reports/big
```

```text
Input: big
Files: discovered 2, processed 1, skipped 1, failed 0
IOCs: 1 unique (ipv4 1, domain 0, url 0, md5 0, sha1 0, sha256 0)
Rejected candidates: 0
Warning [over_size_limit]: big.log: 1320000 bytes exceeds limit of 1048576 bytes, skipped
Output: reports\big\lucent_iocs.json
Status: completed_with_warnings
```

On Windows, Python writes `\n` as two bytes, so `big.log` is 1,320,000 bytes; on Linux and macOS it is 1,200,000 bytes, and the warning shows that number.

If every file is skipped, there is nothing to report and Lucent stops:

```
lucent scan big/big.log --max-file-size 1
```

```text
Error: no files were processed
```

Exit code: `1`.

---

## 12. Working with CSV output

The CSV report has one row per unique IOC, in the same order as the JSON report, with this header:

```text
type,value,validation_status,occurrences,source_count,original_values,sources
```

- `original_values` and `sources` are lists, stored as compact JSON text inside the cell (see the example in section 9). Decode them with a JSON parser.
- Files are UTF-8 without a byte-order mark, with `\r\n` line endings (standard CSV).
- Formula protection: any cell that starts with `=`, `+`, `-`, `@`, a tab or a carriage return gets a leading `'`, so spreadsheet programs do not run it as a formula. This applies to CSV only; the JSON report is never altered.
- The CSV holds the same IOCs as the JSON report but not the `scan`, `summary`, `warnings` or `errors` sections. Use `--format both` if you need those as well.

Example: list each IOC with the files it came from. Save this as `helpers/read_csv.py`:

```python
# Usage: python helpers/read_csv.py PATH_TO_lucent_iocs.csv
# Prints each IOC with the files it came from.
import csv
import json
import sys

with open(sys.argv[1], encoding="utf-8", newline="") as fh:
    for row in csv.DictReader(fh):
        sources = json.loads(row["sources"])
        files = sorted({source["file"] for source in sources})
        print(f"{row['type']:<7} {row['value']}  <- {', '.join(files)}")
```

```
lucent scan samples --format csv --output-dir reports/csv
python helpers/read_csv.py reports/csv/lucent_iocs.csv
```

```text
ipv4    192.0.2.15  <- sample_logs.log
ipv4    192.0.2.16  <- sample_logs.log
ipv4    192.0.2.44  <- sample_events.json
ipv4    198.51.100.200  <- sample_logs.log
ipv4    198.51.100.23  <- sample_logs.log
ipv4    203.0.113.10  <- incident_report.txt
ipv4    203.0.113.50  <- sample_iocs.csv
ipv4    203.0.113.77  <- sample_logs.log
domain  c2.example.net  <- sample_events.json
domain  cdn.example.org  <- sample_logs.log
domain  downloads.example.net  <- sample_logs.log
domain  evil-portal.example.com  <- sample_iocs.csv
domain  example.com  <- incident_report.txt
domain  example.org  <- sample_iocs.csv
domain  files.example.com  <- sample_events.json
domain  login-portal.example.com  <- sample_logs.log
domain  portal.example.com  <- sample_logs.log
domain  update.example.org  <- sample_events.json
domain  www.example.com  <- sample_logs.log
url     http://downloads.example.net/payload/update.exe  <- sample_logs.log
url     http://files.example.com/drop.bin  <- sample_events.json
url     https://c2.example.net/api/checkin  <- sample_events.json
url     https://example.com/test?id=42  <- incident_report.txt
url     https://example.org/invoice?id=99  <- sample_iocs.csv
url     https://login-portal.example.com/verify?id=7781  <- sample_logs.log
url     https://www.example.com/index.html  <- sample_logs.log
md5     d41d8cd98f00b204e9800998ecf8427e  <- sample_iocs.csv, sample_logs.log
sha1    da39a3ee5e6b4b0d3255bfef95601890afd80709  <- sample_events.json
sha256  aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  <- incident_report.txt
sha256  e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855  <- sample_logs.log
```

Note that IPs sort as text (`198.51.100.200` before `198.51.100.23`), not numerically.

---

## 13. Defanged indicators

**Supported** (upper or lower case):

| Written as | Read as | Where |
|---|---|---|
| `[.]` `(.)` `{.}` `[dot]` `(dot)` | `.` | IP addresses, domains, and the host part of URLs |
| `hxxp` / `hxxps` | `http` / `https` | URL scheme |
| `[://]` and `[:]//` | `://` | After the URL scheme |

**Not supported:** spaced dots (`example . com`), words (`example dot com`), `[@]`, backslash-escaped dots, half brackets (`example[.com`), look-alike Unicode characters, and other scheme rewrites such as `fxp://`.

Inside a URL, only the scheme and the host are un-defanged. The path, query and fragment are kept exactly as written, so `/file[.]txt` stays `/file[.]txt`.

Try it. Create `demo/defang.txt`:

```text
a1.example[.]com
a2.example(.)com
a3.example{.}com
a4.example[dot]com
a5.example(DOT)com
198.51.100[.]5
hxxp://example[.]org/one
hxxps[://]example[.]org/two
hXXps[:]//example[.]org/three/file[.]txt
b1.example . net
b2 dot example dot net
b3.example[.net
```

```
lucent scan demo/defang.txt
```

```text
Input: defang.txt
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 10 unique (ipv4 1, domain 6, url 3, md5 0, sha1 0, sha256 0)
Rejected candidates: 2 (unknown_tld 2)
┌────────┬─────────────┬─────────┬──────────────────────────────────────┐
│ type   │ occurrences │ sources │ value                                │
├────────┼─────────────┼─────────┼──────────────────────────────────────┤
│ ipv4   │ 1           │ 1       │ 198.51.100.5                         │
│ domain │ 1           │ 1       │ a1.example.com                       │
│ domain │ 1           │ 1       │ a2.example.com                       │
│ domain │ 1           │ 1       │ a3.example.com                       │
│ domain │ 1           │ 1       │ a4.example.com                       │
│ domain │ 1           │ 1       │ a5.example.com                       │
│ domain │ 3           │ 3       │ example.org                          │
│ url    │ 1           │ 1       │ http://example.org/one               │
│ url    │ 1           │ 1       │ https://example.org/three/file[.]txt │
│ url    │ 1           │ 1       │ https://example.org/two              │
└────────┴─────────────┴─────────┴──────────────────────────────────────┘
Status: completed
```

- All supported forms were recovered. `example.org` has 3 sources: the hosts of the three URLs.
- None of the three unsupported lines (`b1`, `b2`, `b3`) produced an IOC. The two `unknown_tld` rejections come from `b1.example . net` and `b3.example[.net`: Lucent sees `b1.example` and `b3.example`, and `example` is not a top-level domain.

---

## 14. Rejected candidates

A rejected candidate looked like an IOC but failed validation. Rejections are counted per occurrence in `summary.rejected_candidates`; the rejected text itself is not listed.

| Reason | Meaning | Example |
|---|---|---|
| `invalid_ipv4` | An octet over 255, or a leading zero | `999.10.10.10`, `010.0.0.1` |
| `invalid_domain` | Breaks domain rules: fewer than two labels, a label over 63 characters, a label starting or ending with `-`, or more than 253 characters in total | a 4 × 63-character name ending `.com` |
| `unknown_tld` | Last label is not a real top-level domain; typical for file names | `report.pdf`, `update.exe` |
| `ambiguous_file_extension_tld` | A bare, non-defanged domain whose TLD is also a common file extension | `invoice.zip` |
| `invalid_url` | Bad port (not 1–65535), or a host that is not a valid IPv4 address or domain, including single-word internal hosts | `http://intranet/`, `https://example.com:70000/` |
| `unsupported_host` | URL host is an IPv6 address | `https://[2001:db8::5]/` |
| `url_too_long` | URL longer than 2,048 characters | `https://example.com/` + 2,100 characters |

To see all seven, save this as `helpers/make_rejects.py`:

```python
# Writes demo/rejects.txt: one line per Lucent rejection reason.
lines = [
    "999.10.10.10",                              # invalid_ipv4
    ".".join(["a" * 63] * 4) + ".com",           # invalid_domain (over 253 characters)
    "report.pdf",                                # unknown_tld
    "invoice.zip",                               # ambiguous_file_extension_tld
    "http://intranet/",                          # invalid_url
    "https://[2001:db8::5]/",                    # unsupported_host
    "https://example.com/" + "a" * 2100,         # url_too_long
]
with open("demo/rejects.txt", "w", encoding="utf-8", newline="\n") as fh:
    fh.write("\n".join(lines) + "\n")
print("wrote demo/rejects.txt")
```

```
python helpers/make_rejects.py
lucent scan demo/rejects.txt
```

```text
wrote demo/rejects.txt
Input: rejects.txt
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 0 unique (ipv4 0, domain 0, url 0, md5 0, sha1 0, sha256 0)
Rejected candidates: 7 (ambiguous_file_extension_tld 1, invalid_domain 1, invalid_ipv4 1, invalid_url 1, unknown_tld 1, unsupported_host 1, url_too_long 1)
Status: completed
```

Finding zero IOCs is a normal, successful result (exit code 0).

### Ambiguous TLDs and `--allow-ambiguous-tlds`

`zip`, `mov`, `sh`, `py`, `pl`, `rs`, `md`, `ps`, `so`, `cab` and `one` are real top-level domains but also common file extensions. A bare, non-defanged name such as `invoice.zip` is therefore rejected. The same name **is** accepted when it is defanged (`invoice[.]zip`) or is the host of a URL (`https://invoice.zip/`), because those are clear signs it is meant as a domain.

The trade-off: real domains in those country-code TLDs (for example `example.pl`) are also rejected when written plainly. They still show in the rejected count. To accept them, add `--allow-ambiguous-tlds`:

```
lucent scan samples/incident_report.txt --allow-ambiguous-tlds
```

```text
Input: incident_report.txt
Files: discovered 1, processed 1, skipped 0, failed 0
IOCs: 5 unique (ipv4 1, domain 2, url 1, md5 0, sha1 0, sha256 1)
Rejected candidates: 0
┌────────┬─────────────┬─────────┬────────────────────────────────────────────┐
│ type   │ occurrences │ sources │ value                                      │
├────────┼─────────────┼─────────┼────────────────────────────────────────────┤
│ ipv4   │ 2           │ 2       │ 203.0.113.10                               │
│ domain │ 2           │ 2       │ example.com                                │
│ domain │ 1           │ 1       │ invoice.zip                                │
│ url    │ 1           │ 1       │ https://example.com/test?id=42             │
│ sha256 │ 1           │ 1       │ aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa │
│        │             │         │ aaaaaaaaaaaaaaaaaaaaaa                     │
└────────┴─────────────┴─────────┴────────────────────────────────────────────┘
Status: completed
```

Compare with Quick start step 1: `invoice.zip` is now reported, and nothing is rejected.

---

## 15. Warnings, errors and scan status

### Warnings

A warning means something was skipped or adjusted, but the scan carried on. Each appears in the `warnings` list as `{code, path, message}` and as a `Warning [...]` line in the terminal.

| Code | Cause | Shown in |
|---|---|---|
| `unsupported_extension` | A file in the folder has an extension Lucent does not read | below |
| `over_size_limit` | A file is larger than `--max-file-size` | §11 |
| `file_limit_reached` | More files than `--max-files` (reported once) | §11 |
| `decode_replacement` | A file was not valid UTF-8; bad bytes were replaced | §10 |
| `jsonl_line_invalid` | A line of a `.jsonl` / `.ndjson` file is not valid JSON | §10 |
| `symlink_skipped` | A symbolic link found inside a folder was not followed | not demonstrated in this guide |

### Errors

An error means a whole file could not be read or parsed. That file contributes nothing to the report, and the rest of the scan continues. Each appears in the `errors` list:

| Field | Meaning |
|---|---|
| `path` | The file, relative to the scanned folder |
| `stage` | `read` (could not open or read) or `parse` (invalid JSON, CSV error) |
| `error_type` | The kind of error, for example `JSONDecodeError` or `PermissionError` |
| `message` | What went wrong. It never includes the file's contents. |
| `recoverable` | `true`: the scan carried on without this file |

### Scan status

| Status | When |
|---|---|
| `completed` | No warnings and no errors |
| `completed_with_warnings` | At least one warning, no failed files |
| `partial` | At least one file failed |

`tests/fixtures/mixed` contains a good file, an empty file, a large log, a broken JSON file and an unsupported `.bin` file:

```
lucent scan tests/fixtures/mixed --output-dir reports/mixed
```

```text
Input: mixed
Files: discovered 5, processed 3, skipped 1, failed 1
IOCs: 68 unique (ipv4 65, domain 1, url 1, md5 0, sha1 1, sha256 0)
Rejected candidates: 0
Warning [unsupported_extension]: unsupported.bin: unsupported file extension, skipped
Error [parse] JSONDecodeError: malformed.json: invalid JSON at line 2
Output: reports\mixed\lucent_iocs.json
Status: partial
```

Exit code: `3`. The matching part of `reports/mixed/lucent_iocs.json`:

```json
{
  "status": "partial",
  "files": {
    "discovered": 5,
    "processed": 3,
    "skipped": 1,
    "failed": 1
  },
  "warnings": [
    {
      "code": "unsupported_extension",
      "path": "unsupported.bin",
      "message": "unsupported.bin: unsupported file extension, skipped"
    }
  ],
  "errors": [
    {
      "path": "malformed.json",
      "stage": "parse",
      "error_type": "JSONDecodeError",
      "message": "malformed.json: invalid JSON at line 2",
      "recoverable": true
    }
  ]
}
```

(`status` and `files` are inside `scan` in the real report; they are grouped here for readability.)

With `--quiet`, only the error lines and the status are printed:

```
lucent scan tests/fixtures/mixed --quiet
```

```text
Error [parse] JSONDecodeError: malformed.json: invalid JSON at line 2
Status: partial
```

A folder with warnings but no failures. By this point `demo/` holds the five practice files from sections 10, 13 and 14:

```
lucent scan demo --output-dir reports/demo
```

```text
Input: demo
Files: discovered 5, processed 5, skipped 0, failed 0
IOCs: 17 unique (ipv4 4, domain 9, url 4, md5 0, sha1 0, sha256 0)
Rejected candidates: 9 (ambiguous_file_extension_tld 1, invalid_domain 1, invalid_ipv4 1, invalid_url 1, unknown_tld 3, unsupported_host 1, url_too_long 1)
Warning [jsonl_line_invalid]: events.jsonl: line 3 is not valid JSON, skipped
Warning [decode_replacement]: legacy.txt: not valid UTF-8; undecodable bytes replaced
Output: reports\demo\lucent_iocs.json
Status: completed_with_warnings
```

Exit code: `0`.

---

## 16. Exit codes and `--strict`

| Code | When | Example in this guide |
|---|---|---|
| `0` | Status `completed` or `completed_with_warnings` (without `--strict`) | Quick start |
| `1` | Input missing, not a file or folder, or an unsupported single file; no files processed; report already exists without `--force`; output would overwrite the input; or no requested report could be written | §9, §10, §11 |
| `2` | Invalid or conflicting options | §9 |
| `3` | Status `partial`; or one of two requested reports (`--format both`) could not be written while the other was; or `--strict` with any warning | §11, §15, below |

When Lucent stops with exit code 1, it writes no report and prints `Error: ...` to standard error. For example, a missing input gives `Error: input not found: missing.txt`.

### Reading the exit code

```powershell
PS> lucent scan tests/fixtures/mixed --quiet; "exit code: $LASTEXITCODE"
```

```text
Error [parse] JSONDecodeError: malformed.json: invalid JSON at line 2
Status: partial
exit code: 3
```

```bash
$ lucent scan tests/fixtures/mixed --quiet; echo "exit code: $?"
```

```text
Error [parse] JSONDecodeError: malformed.json: invalid JSON at line 2
Status: partial
exit code: 3
```

### `--strict`

`--strict` turns any warning into exit code 3. It changes only the exit code: what is scanned and what is written stay the same, apart from `"strict": true` in the report.

```
lucent scan demo --quiet
```

```text
Status: completed_with_warnings
```

Exit code: `0`.

```
lucent scan demo --strict --quiet
```

```text
Status: completed_with_warnings
```

Exit code: `3`.

---

## 17. Recipes

### Scan a case folder into both formats

```
lucent scan samples/ --recursive --format both --output-dir reports/
```

Output and files as in Quick start step 3. Add `--force` to refresh the reports later.

### Print a short summary with Python

Save as `helpers/summary.py`:

```python
# Reads a Lucent JSON report from stdin and prints a short summary.
import json
import sys

# utf-8-sig also accepts the byte-order mark Windows PowerShell adds when piping.
report = json.loads(sys.stdin.buffer.read().decode("utf-8-sig"))
summary = report["summary"]
print("status:", report["scan"]["status"])
print("unique IOCs:", summary["total_unique_iocs"])
for ioc_type, count in summary["by_type"].items():
    if count:
        print(f"  {ioc_type}: {count}")
print("rejected:", summary["rejected_candidates"]["total"])
```

```powershell
PS> lucent scan samples --output - 2>$null | python helpers/summary.py
```

```bash
$ lucent scan samples --output - 2>/dev/null | python helpers/summary.py
```

Both print:

```text
status: completed
unique IOCs: 30
  ipv4: 8
  domain: 11
  url: 7
  md5: 1
  sha1: 1
  sha256: 2
rejected: 5
```

`2>$null` / `2>/dev/null` hides the human-readable summary, which goes to standard error.

### Limit noisy indicators: `--max-sources-per-ioc`

An IOC seen in thousands of places can make a report huge. Keep only the first N sources (sorted) while still counting all of them:

```
lucent scan samples --max-sources-per-ioc 2 --output reports/capped.json
```

```text
Input: samples
Files: discovered 4, processed 4, skipped 0, failed 0
IOCs: 30 unique (ipv4 8, domain 11, url 7, md5 1, sha1 1, sha256 2)
Rejected candidates: 5 (ambiguous_file_extension_tld 1, invalid_ipv4 1, unknown_tld 3)
Output: reports\capped.json
Status: completed
```

In `reports/capped.json`, `192.0.2.15` was seen on 4 lines but only 2 sources are kept:

```json
{
  "type": "ipv4",
  "value": "192.0.2.15",
  "validation_status": "valid_syntax",
  "occurrences": 4,
  "source_count": 4,
  "sources_truncated": true,
  "original_values": [
    "192.0.2.15"
  ],
  "original_values_truncated": false,
  "sources": [
    {
      "file": "sample_logs.log",
      "line": 4
    },
    {
      "file": "sample_logs.log",
      "line": 6
    }
  ]
}
```

### See which files are read: `--verbose`

```
lucent scan samples --verbose --output-dir reports/verbose
```

```text
Processed: incident_report.txt
Processed: sample_events.json
Processed: sample_iocs.csv
Processed: sample_logs.log
Input: samples
Files: discovered 4, processed 4, skipped 0, failed 0
IOCs: 30 unique (ipv4 8, domain 11, url 7, md5 1, sha1 1, sha256 2)
Rejected candidates: 5 (ambiguous_file_extension_tld 1, invalid_ipv4 1, unknown_tld 3)
Output: reports\verbose\lucent_iocs.json
Status: completed
```

A file that fails is listed as `Failed: <file>`, followed by a full Python traceback. Without `--verbose`, Lucent never prints tracebacks.

### Use Lucent in a script

Use `--quiet` and check the exit code.

```powershell
PS> lucent scan samples --quiet --output-dir reports/nightly --force; if ($LASTEXITCODE -eq 0) { "scan ok" } else { "scan needs attention" }
```

```bash
$ lucent scan samples --quiet --output-dir reports/nightly --force; if [ $? -eq 0 ]; then echo "scan ok"; else echo "scan needs attention"; fi
```

```text
Status: completed
scan ok
```

Run against `tests/fixtures/mixed` instead, the same line prints:

```text
Error [parse] JSONDecodeError: malformed.json: invalid JSON at line 2
Status: partial
scan needs attention
```

### Run without the `lucent` launcher

```
python -m lucent_ioc scan samples/incident_report.txt --quiet
```

```text
Status: completed
```

---

## 18. Troubleshooting

| What you see | Cause | Fix |
|---|---|---|
| PowerShell: `The term 'lucent' is not recognized as the name of a cmdlet, function, script file, or operable program.` bash: `lucent: command not found` | The virtual environment is not active, or Lucent is not installed in it | Activate it (§5 step 3) or install it (§5 step 4). `python -m lucent_ioc` also works once installed. |
| `Error: output file ... already exists (use --force to overwrite)` | A report with that name is already there | Add `--force`, or choose another `--output` / `--output-dir` |
| `Error: output path ... is the input file` | `--output` points at the file being scanned | Choose a different output path. `--force` does not override this. |
| `Invalid value: --format csv requires --output or --output-dir.` | CSV cannot be shown in the terminal | Add `--output FILE`, `--output -` or `--output-dir DIR` |
| `Invalid value: --format both requires --output-dir.` | Two files need a folder | Use `--output-dir DIR` |
| `Error: no files were processed` | The folder has no supported files, they are all in subfolders (add `--recursive`), or every file was over the size limit | Check the path, add `--recursive`, or raise `--max-file-size` |
| `Error: unsupported file extension '...'` | A single file with an extension Lucent does not read | Rename it with a supported extension, if it is text, or scan its folder |
| `Error: input not found: ...` | The path does not exist | Check the path relative to your current folder |
| Exit code 3 and `Status: partial` | At least one file could not be read or parsed | See the `Error [...]` lines or the `errors` list. The other files were still scanned. |
| A file name such as `report.pdf` is not reported | Its last part is not a real TLD (`unknown_tld`) | Expected |
| `invoice.zip` or `example.pl` is not reported | Ambiguous TLD rule (§14) | Defang it in the source, or use `--allow-ambiguous-tlds` |
| A domain in a URL path (`/files/other.com`) or an email domain is not reported | URL text and email addresses are masked before domains are searched | Expected; the URL itself and its host are reported |
| Python cannot read JSON saved with `> file` in PowerShell | PowerShell re-encoded the output | Use `--output FILE` instead (§9) |
| The table shows `showing 50 of N` | The terminal table is capped at 50 rows | Write a report with `--output` or `--output-dir` to see everything |
| Output paths show `\` | Windows path style | Expected; the paths inside reports always use `/` |

---

## 19. Known limitations

- **Syntax only.** Lucent says nothing about whether an indicator is malicious, and makes no lookups to find out.
- **Hash look-alikes.** Any run of exactly 32, 40 or 64 hex characters (for example an undashed GUID or an API token) is reported as `md5`, `sha1` or `sha256`.
- **Ambiguous TLDs.** Plain domains ending in `.zip`, `.mov`, `.sh`, `.py`, `.pl`, `.rs`, `.md`, `.ps`, `.so`, `.cab` or `.one` are rejected unless defanged, inside a URL, or `--allow-ambiguous-tlds` is used.
- **Masked text.** Domains that appear only inside a URL's path or query, or inside an email address, are not reported on their own.
- **Not supported:** IPv6 addresses, email addresses as IOCs, non-ASCII (Unicode) domain names, and URLs with schemes other than `http`, `https`, `hxxp` and `hxxps`. Punycode domains (`xn--...`) are accepted as written.
- **Internal hostnames.** Single-word hosts such as `http://intranet/`, and names ending in a non-public suffix such as `server.local`, are rejected.
- **JSON details.** JSON keys are not scanned, and `.json` sources have a path but no line number.
- **URL length.** URLs longer than 2,048 characters are rejected (`url_too_long`).
- **Top-level domains.** The bundled TLD list is a snapshot (`tld_snapshot` in each report). TLDs added later by IANA are unknown until the list is refreshed.
