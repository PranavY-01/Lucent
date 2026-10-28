"""Static configuration: defaults, limits, codes and names. No I/O."""

from __future__ import annotations

TOOL_NAME = "Lucent"
SCHEMA_VERSION = "1.0"
DISTRIBUTION_NAME = "lucent-ioc"

# Limits (§B4.7)
DEFAULT_MAX_FILE_SIZE_MB = 50
BYTES_PER_MB = 1024 * 1024
DEFAULT_MAX_FILE_SIZE_BYTES = DEFAULT_MAX_FILE_SIZE_MB * BYTES_PER_MB  # 52,428,800
DEFAULT_MAX_FILES = 10_000
DEFAULT_MAX_SOURCES_PER_IOC = 100
MAX_ORIGINAL_VALUES_PER_IOC = 20
MAX_URL_LENGTH = 2_048

# Terminal table cap when no destination is given (§B10.2)
TERMINAL_TABLE_ROWS = 50

# Supported input extensions (lowercase, with dot)
TEXT_EXTENSIONS = frozenset({".txt", ".log", ".md"})
CSV_EXTENSIONS = frozenset({".csv"})
JSON_EXTENSIONS = frozenset({".json"})
JSONL_EXTENSIONS = frozenset({".jsonl", ".ndjson"})
SUPPORTED_EXTENSIONS = TEXT_EXTENSIONS | CSV_EXTENSIONS | JSON_EXTENSIONS | JSONL_EXTENSIONS

# IOC type order (§B9.1); also the report sort order
IOC_TYPE_ORDER = ("ipv4", "domain", "url", "md5", "sha1", "sha256")

# Rejection reasons (§B9.2)
REASON_INVALID_IPV4 = "invalid_ipv4"
REASON_INVALID_DOMAIN = "invalid_domain"
REASON_UNKNOWN_TLD = "unknown_tld"
REASON_AMBIGUOUS_TLD = "ambiguous_file_extension_tld"
REASON_INVALID_URL = "invalid_url"
REASON_UNSUPPORTED_HOST = "unsupported_host"
REASON_URL_TOO_LONG = "url_too_long"
REJECTION_REASONS = (
    REASON_INVALID_IPV4,
    REASON_INVALID_DOMAIN,
    REASON_UNKNOWN_TLD,
    REASON_AMBIGUOUS_TLD,
    REASON_INVALID_URL,
    REASON_UNSUPPORTED_HOST,
    REASON_URL_TOO_LONG,
)

# Warning codes (§B9.2)
WARN_UNSUPPORTED_EXTENSION = "unsupported_extension"
WARN_SYMLINK_SKIPPED = "symlink_skipped"
WARN_OVER_SIZE_LIMIT = "over_size_limit"
WARN_FILE_LIMIT_REACHED = "file_limit_reached"
WARN_DECODE_REPLACEMENT = "decode_replacement"
WARN_JSONL_LINE_INVALID = "jsonl_line_invalid"
WARNING_CODES = (
    WARN_UNSUPPORTED_EXTENSION,
    WARN_SYMLINK_SKIPPED,
    WARN_OVER_SIZE_LIMIT,
    WARN_FILE_LIMIT_REACHED,
    WARN_DECODE_REPLACEMENT,
    WARN_JSONL_LINE_INVALID,
)

# Output file names for --output-dir (D-4)
OUTPUT_JSON_NAME = "lucent_iocs.json"
OUTPUT_CSV_NAME = "lucent_iocs.csv"

# CSV export (§B9.6)
CSV_HEADER = (
    "type",
    "value",
    "validation_status",
    "occurrences",
    "source_count",
    "original_values",
    "sources",
)
CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")

# Exit codes (§B10.3)
EXIT_OK = 0
EXIT_FATAL = 1
EXIT_USAGE = 2
EXIT_PARTIAL = 3
