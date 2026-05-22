"""OWASP CRS rule file parser.

Extracts @rx (regex) patterns from CRS .conf files, filtered by paranoia level,
and returns them as a list of individually compiled patterns — one per CRS rule.
"""

import logging
import re
from pathlib import Path

logger = logging.getLogger(__name__)

CRS_DIR = Path(__file__).parent / 'crs'

_RX_RE = re.compile(r'"@rx\s+((?:[^"\\]|\\.)*)"')
_PL_RE = re.compile(r"tag:'paranoia-level/(\d+)'")
# CRS patterns often start with (?i); strip it and compile with IGNORECASE instead
_LEADING_FLAG_RE = re.compile(r'^\(\?[a-z]+\)')


def _load_rx_patterns(conf_file: Path, max_paranoia: int) -> list[str]:
    text = conf_file.read_text(encoding='utf-8', errors='replace')
    # Join continuation lines so each SecRule block is one line
    text = re.sub(r'\\\n[ \t]*', ' ', text)

    patterns = []
    for line in text.splitlines():
        if '@rx' not in line:
            continue
        pl_match = _PL_RE.search(line)
        if pl_match and int(pl_match.group(1)) > max_paranoia:
            continue
        rx_match = _RX_RE.search(line)
        if rx_match:
            patterns.append(rx_match.group(1))
    return patterns


def build_patterns(conf_files: list[str], max_paranoia: int = 1) -> list[re.Pattern]:
    """Return a list of individually compiled CRS @rx patterns.

    Each element corresponds to one CRS SecRule. Patterns with
    Python-incompatible regex syntax are silently skipped.
    Returns an empty list if no files are found or no valid patterns exist.
    """
    all_patterns = []
    for filename in conf_files:
        path = CRS_DIR / filename
        if not path.exists():
            logger.warning(f"CRS rule file not found: {path}")
            continue
        all_patterns.extend(_load_rx_patterns(path, max_paranoia))

    valid = []
    skipped = 0
    for p in all_patterns:
        # Strip leading flag group e.g. (?i) — re.IGNORECASE is applied instead
        p = _LEADING_FLAG_RE.sub('', p)
        try:
            valid.append(re.compile(p, re.IGNORECASE))
        except re.error:
            skipped += 1

    if skipped:
        logger.debug(f"Skipped {skipped} CRS pattern(s) with unsupported regex syntax")

    return valid
