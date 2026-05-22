"""Web server log parser for Apache/NGINX combined log format.

Parses log files line by line and extracts structured fields into LogEntry objects.
Every line produces exactly one LogEntry — malformed lines are represented with
placeholder '-' values to ensure a consistent output schema. Includes CRS-based
attack detection for security analysis.

Supported Log Formats:

1. Standard Apache/NGINX combined format:
   host ident authuser [timestamp] "method url protocol" status size "referrer" "user_agent"
   Example: 192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"

2. Non-standard raw request format (non-HTTP requests from bots/scanners/protocols):
   host ident authuser [timestamp] "raw_content" status size "referrer" "user_agent" [extra...]

   This handles:
   - Empty requests: "" (no content)
   - Binary/protocol data: "\x13BitTorrent protocol..."
   - Other non-HTTP content

   Examples:
     157.230.42.58 - - [29/Dec/2025:13:58:22 +0700] "" 400 0 "-" "-" "_" "-"
     74.82.60.74 - - [22/Jan/2019:08:27:26 +0330] "\x13BitTorrent protocol..." 400 166 "-" "-"

   Note: method and protocol are set to '-', raw request content is stored in url field.
"""

import re
import base64
import logging
import time
from dataclasses import dataclass, fields
from typing import Generator
from urllib.parse import unquote

from scqlog.attack_detector import detect_attacks

logger = logging.getLogger(__name__)

# Apache/NGINX combined log format regex pattern (standard request)
LOG_PATTERN = re.compile(
    r'^(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<authuser>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+'
    r'(?P<url>\S+)\s+'
    r'(?P<protocol>[^"]+)"\s+'
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)\s*'
    r'(?:"(?P<referrer>[^"]*)"\s*)?'
    r'(?:"(?P<user_agent>[^"]*)"\s*)?'
    r'(?P<extra>.*)?$'
)

# Non-standard log format with raw/non-HTTP request content
# Handles empty requests ("") and binary/non-HTTP data (e.g., BitTorrent protocol)
# Examples:
#   157.230.42.58 - - [29/Dec/2025:13:58:22 +0700] "" 400 0 "-" "-" "_" "-"
#   74.82.60.74 - - [22/Jan/2019:08:27:26 +0330] "\x13BitTorrent protocol..." 400 166 "-" "-"
LOG_PATTERN_RAW_REQUEST = re.compile(
    r'^(?P<host>\S+)\s+'
    r'(?P<ident>\S+)\s+'
    r'(?P<authuser>\S+)\s+'
    r'\[(?P<timestamp>[^\]]+)\]\s+'
    r'"(?P<raw_request>[^"]*)"\s+'  # Capture any content (including empty) as raw_request
    r'(?P<status>\d+)\s+'
    r'(?P<size>\S+)\s*'
    r'(?:"(?P<referrer>[^"]*)"\s*)?'
    r'(?:"(?P<user_agent>[^"]*)"\s*)?'
    r'(?P<extra>.*)?$'
)

# Pattern to detect likely Base64 strings (only alphanumeric, +, /, =)
BASE64_PATTERN = re.compile(r'^[A-Za-z0-9+/]+=*$')


@dataclass
class LogEntry:
    """Represents a single parsed log entry with all extracted fields and attack detection."""

    # Core log fields
    line_number: int
    host: str
    ident: str
    authuser: str
    timestamp: str
    method: str
    url: str
    protocol: str
    status: str
    size: str
    referrer: str
    user_agent: str
    extra: str

    # Attack detection columns (number of CRS rules matched, 0 = none)
    sqli_score: int
    xss_score: int
    path_traversal_score: int
    cmd_injection_score: int
    rce_score: int
    lfi_score: int
    rfi_score: int
    webshell_score: int


# Column names derived from LogEntry fields — the complete Parquet/DataFrame schema.
COLUMNS = [field.name for field in fields(LogEntry)]


def is_likely_base64(s: str) -> bool:
    """
    Check if a string appears to be Base64-encoded.

    Args:
        s: String to check

    Returns:
        True if the string looks like valid Base64
    """
    if len(s) < 4:
        return False

    if not BASE64_PATTERN.match(s):
        return False

    padding = s.count('=')
    if padding > 2:
        return False
    if padding > 0 and not s.endswith('=' * padding):
        return False

    return True


def decode_value(value: str) -> str:
    """
    Decode a URL-encoded and potentially Base64-encoded string.

    Decoding order:
    1. URL decode (percent-encoding)
    2. If result looks like Base64, attempt Base64 decode

    Args:
        value: The encoded string

    Returns:
        Decoded string, or original value if decoding fails
    """
    if not value or value == '-':
        return value

    try:
        decoded = unquote(value)

        if is_likely_base64(decoded):
            try:
                b64_decoded = base64.b64decode(decoded).decode('utf-8', errors='replace')
                if b64_decoded.isprintable() or '\n' in b64_decoded or '\t' in b64_decoded:
                    return b64_decoded
            except Exception:
                pass

        return decoded
    except Exception:
        return value


def _create_fallback_entry(line_number: int) -> LogEntry:
    """
    Create a fallback LogEntry with placeholder values for non-matching lines.

    Args:
        line_number: The line number in the original file

    Returns:
        LogEntry with all fields set to '-' except line_number
    """
    return LogEntry(
        line_number=line_number,
        host='-',
        ident='-',
        authuser='-',
        timestamp='-',
        method='-',
        url='-',
        protocol='-',
        status='-',
        size='-',
        referrer='-',
        user_agent='-',
        extra='-',
        sqli_score=0,
        xss_score=0,
        path_traversal_score=0,
        cmd_injection_score=0,
        rce_score=0,
        lfi_score=0,
        rfi_score=0,
        webshell_score=0,
    )


def _parse_standard_log(groups: dict, line_number: int) -> LogEntry:
    """
    Create a LogEntry from standard log format match groups.

    Args:
        groups: Regex match groups from LOG_PATTERN
        line_number: The line number in the original file

    Returns:
        LogEntry with all parsed fields
    """
    # Decode URL and referrer for readability
    url = decode_value(groups['url'])
    referrer = decode_value(groups.get('referrer') or '-')

    # Perform attack detection on the URL
    attacks = detect_attacks(url)

    return LogEntry(
        line_number=line_number,
        host=groups['host'],
        ident=groups['ident'],
        authuser=groups['authuser'],
        timestamp=groups['timestamp'],
        method=groups['method'],
        url=url,
        protocol=groups['protocol'],
        status=groups['status'],
        size=groups['size'],
        referrer=referrer,
        user_agent=groups.get('user_agent') or '-',
        extra=groups.get('extra') or '',
        # Attack detection results
        sqli_score=attacks.sqli_score,
        xss_score=attacks.xss_score,
        path_traversal_score=attacks.path_traversal_score,
        cmd_injection_score=attacks.cmd_injection_score,
        rce_score=attacks.rce_score,
        lfi_score=attacks.lfi_score,
        rfi_score=attacks.rfi_score,
        webshell_score=attacks.webshell_score,
    )


def _parse_raw_request_log(groups: dict, line_number: int) -> LogEntry:
    """
    Create a LogEntry from non-HTTP request log format match groups.

    Handles log lines where the request field contains non-HTTP content:
    - Empty requests ("")
    - Binary data (e.g., BitTorrent protocol)
    - Other non-HTTP protocol data

    The raw request content is stored in the `url` field; empty raw content
    is normalised to '-'. Method and protocol are set to '-' since this is
    not a valid HTTP request.

    Args:
        groups: Regex match groups from LOG_PATTERN_RAW_REQUEST
        line_number: The line number in the original file

    Returns:
        LogEntry with available fields parsed, raw request stored in url
    """
    referrer = decode_value(groups.get('referrer') or '-')
    raw_request = groups.get('raw_request') or ''

    # Store raw request content in url field (empty string becomes '-')
    url = raw_request if raw_request else '-'

    # Perform attack detection on raw request content (may contain attack patterns)
    attacks = detect_attacks(url) if url != '-' else None

    return LogEntry(
        line_number=line_number,
        host=groups['host'],
        ident=groups['ident'],
        authuser=groups['authuser'],
        timestamp=groups['timestamp'],
        method='-',    # Non-HTTP request - no method
        url=url,       # Raw request content preserved here
        protocol='-',  # Non-HTTP request - no protocol
        status=groups['status'],
        size=groups['size'],
        referrer=referrer,
        user_agent=groups.get('user_agent') or '-',
        extra=groups.get('extra') or '',
        # Attack detection on raw request content
        sqli_score=attacks.sqli_score if attacks else 0,
        xss_score=attacks.xss_score if attacks else 0,
        path_traversal_score=attacks.path_traversal_score if attacks else 0,
        cmd_injection_score=attacks.cmd_injection_score if attacks else 0,
        rce_score=attacks.rce_score if attacks else 0,
        lfi_score=attacks.lfi_score if attacks else 0,
        rfi_score=attacks.rfi_score if attacks else 0,
        webshell_score=attacks.webshell_score if attacks else 0,
    )


def parse_line(line: str, line_number: int) -> LogEntry:
    """
    Parse a single log line into a LogEntry with attack detection.

    Attempts to match the line against known log formats in order:
    1. Standard Apache/NGINX combined format with full HTTP request
    2. Non-standard format with raw/non-HTTP request content (empty, binary, etc.)

    For non-HTTP requests, the raw content is preserved in the url field,
    while method and protocol are set to '-'.

    Always returns a valid LogEntry. If no pattern matches, returns a
    fallback entry with all fields set to '-'.

    Args:
        line: Raw log line string
        line_number: The line number in the original file

    Returns:
        LogEntry with parsed fields, or fallback entry with '-' values if parsing fails
    """
    line = line.strip()
    if not line:
        return _create_fallback_entry(line_number)

    # Try standard log format first
    match = LOG_PATTERN.match(line)
    if match:
        return _parse_standard_log(match.groupdict(), line_number)

    # Try raw/non-HTTP request format (empty, binary, or other non-HTTP content)
    match = LOG_PATTERN_RAW_REQUEST.match(line)
    if match:
        return _parse_raw_request_log(match.groupdict(), line_number)

    # No pattern matched - return fallback
    return _create_fallback_entry(line_number)


def parse_log_file(filepath: str) -> Generator[LogEntry, None, None]:
    """
    Parse a log file and yield LogEntry objects for each line.

    Every line produces exactly one LogEntry. Lines that do not match the
    expected log format are represented with placeholder '-' values.
    Logs progress every 1,000,000 lines.

    Args:
        filepath: Path to the log file

    Yields:
        LogEntry for each line in the file
    """
    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        total_lines = sum(1 for _ in f)

    logger.info(f"Parsing {filepath}: {total_lines:,} lines total")

    start_time = time.monotonic()

    with open(filepath, 'r', encoding='utf-8', errors='replace') as f:
        for line_num, line in enumerate(f, start=1):
            entry = parse_line(line, line_num)
            if entry.host == '-' and line.strip():
                logger.warning(f"Malformed line at {filepath}:{line_num}")
            if line_num % 1_000_000 == 0:
                elapsed = time.monotonic() - start_time
                rate = line_num / elapsed
                remaining_minutes = (total_lines - line_num) / rate / 60
                logger.info(
                    f"Parsed {line_num:,} / {total_lines:,} lines "
                    f"({line_num * 100 // total_lines}%) — "
                    f"ETC: {remaining_minutes:.1f} min"
                )
            yield entry
