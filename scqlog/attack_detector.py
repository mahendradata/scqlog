"""Rule-based web attack detection using OWASP CRS patterns.

Analyzes URL fields to detect common web attack payloads including
SQL injection, XSS, path traversal, command injection, and more.

Patterns are loaded from OWASP CRS .conf files in scqlog/crs/ on first use,
filtered by paranoia level (Config.CRS_PARANOIA_LEVEL). Lazy initialization
lets CLI/tests mutate Config.CRS_PARANOIA_LEVEL between import time and
the first detect_attacks() call. If a CRS file is missing, the affected
category will have no patterns and will always score 0 — no fallback
regex is used.

Score values are the number of CRS rules that matched (e.g. 3), or 0
if none matched.
"""

import re
import logging
from dataclasses import dataclass

from scqlog.config import Config
from scqlog.crs_loader import build_patterns

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# CRS rule file mapping per attack category
# ---------------------------------------------------------------------------

_CRS_FILES = {
    'sqli':           ['REQUEST-942-APPLICATION-ATTACK-SQLI.conf'],
    'xss':            ['REQUEST-941-APPLICATION-ATTACK-XSS.conf'],
    'path_traversal': ['REQUEST-930-APPLICATION-ATTACK-LFI.conf'],
    'cmd_injection':  ['REQUEST-932-APPLICATION-ATTACK-RCE.conf'],
    'rce':            ['REQUEST-932-APPLICATION-ATTACK-RCE.conf',
                       'REQUEST-933-APPLICATION-ATTACK-PHP.conf'],
    'lfi':            ['REQUEST-930-APPLICATION-ATTACK-LFI.conf'],
    'rfi':            ['REQUEST-931-APPLICATION-ATTACK-RFI.conf'],
    'webshell':       ['REQUEST-933-APPLICATION-ATTACK-PHP.conf'],
}

ATTACK_TYPES: list[str] = list(_CRS_FILES.keys())

ATTACK_COLUMNS: list[str] = [f"{t}_score" for t in ATTACK_TYPES]


# ---------------------------------------------------------------------------
# Lazy pattern loading
#
# PATTERNS is built on first access and re-built if Config.CRS_PARANOIA_LEVEL
# changes between calls. This lets CLI args (parsed in scqlog/cli.py) take effect
# even though attack_detector is imported transitively from parser.py.
# ---------------------------------------------------------------------------

_PATTERNS_CACHE: dict[str, list[re.Pattern]] | None = None
_CACHED_AT_LEVEL: int | None = None


def _build_patterns_for(paranoia_level: int) -> dict[str, list[re.Pattern]]:
    """Build the per-category CRS pattern dict for the given paranoia level."""
    patterns: dict[str, list[re.Pattern]] = {}
    for category, files in _CRS_FILES.items():
        crs = build_patterns(files, max_paranoia=paranoia_level)
        patterns[category] = crs
        if crs:
            logger.debug(
                f"attack_detector: '{category}' loaded {len(crs)} CRS rule(s) (PL<={paranoia_level})"
            )
        else:
            logger.warning(
                f"attack_detector: '{category}' has no CRS rules — scores will always be 0"
            )
    return patterns


def get_patterns() -> dict[str, list[re.Pattern]]:
    """Return the active per-category pattern dict, rebuilding on PL change.

    The result is cached for the current paranoia level so repeated calls
    are O(1). If Config.CRS_PARANOIA_LEVEL is mutated (e.g. by a CLI flag
    or an evaluation script), the cache is invalidated and patterns are
    re-loaded automatically on the next call.
    """
    global _PATTERNS_CACHE, _CACHED_AT_LEVEL
    pl = Config.CRS_PARANOIA_LEVEL
    if _PATTERNS_CACHE is None or _CACHED_AT_LEVEL != pl:
        logger.info(f"Loading OWASP CRS patterns at paranoia level {pl}")
        _PATTERNS_CACHE = _build_patterns_for(pl)
        _CACHED_AT_LEVEL = pl
    return _PATTERNS_CACHE


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def _count_matches(patterns: list[re.Pattern], url: str) -> int:
    """Return the number of rules that matched, or 0 if none."""
    return sum(1 for p in patterns if p.search(url))


@dataclass
class AttackDetectionResult:
    """Results of attack detection for a single URL.

    Each attribute contains the number of CRS rules that matched (e.g. 3),
    or 0 if no rule matched.
    """
    sqli_score: int
    xss_score: int
    path_traversal_score: int
    cmd_injection_score: int
    rce_score: int
    lfi_score: int
    rfi_score: int
    webshell_score: int


def detect_attacks(url: str) -> AttackDetectionResult:
    """Analyze a URL for common web attack patterns."""
    if not url or url == '-':
        return AttackDetectionResult(
            sqli_score=0, xss_score=0, path_traversal_score=0,
            cmd_injection_score=0, rce_score=0, lfi_score=0,
            rfi_score=0, webshell_score=0,
        )

    patterns = get_patterns()
    return AttackDetectionResult(
        sqli_score=           _count_matches(patterns['sqli'],           url),
        xss_score=            _count_matches(patterns['xss'],            url),
        path_traversal_score= _count_matches(patterns['path_traversal'], url),
        cmd_injection_score=  _count_matches(patterns['cmd_injection'],  url),
        rce_score=            _count_matches(patterns['rce'],            url),
        lfi_score=            _count_matches(patterns['lfi'],            url),
        rfi_score=            _count_matches(patterns['rfi'],            url),
        webshell_score=       _count_matches(patterns['webshell'],       url),
    )
