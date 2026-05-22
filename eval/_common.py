"""Shared helpers for the evaluation suite.

Kept dependency-light: stdlib + numpy only.
"""

from __future__ import annotations

from collections import Counter
from pathlib import Path
from typing import Iterable

import numpy as np


def percentile(values: list[int] | np.ndarray, q: float) -> float:
    """Percentile of a sequence; returns nan for empty input."""
    if len(values) == 0:
        return float("nan")
    return float(np.percentile(np.asarray(values), q))


def write_csv(path: Path, header: list[str], rows: Iterable[list]) -> None:
    """Trivial CSV writer (no escaping needed for our scalar outputs)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(",".join(header) + "\n")
        for r in rows:
            f.write(",".join(str(c) for c in r) + "\n")


def fmt_table(header: list[str], rows: list[list]) -> str:
    """Render a markdown table for the summary report."""
    widths = [len(h) for h in header]
    rows_s = [[str(c) for c in r] for r in rows]
    for r in rows_s:
        for i, c in enumerate(r):
            widths[i] = max(widths[i], len(c))
    line = "| " + " | ".join(h.ljust(widths[i]) for i, h in enumerate(header)) + " |"
    sep  = "|-" + "-|-".join("-" * w for w in widths) + "-|"
    body = "\n".join(
        "| " + " | ".join(c.ljust(widths[i]) for i, c in enumerate(r)) + " |"
        for r in rows_s
    )
    return "\n".join([line, sep, body])


def load_urls_from_log(log_path: Path, max_lines: int | None = None) -> list[str]:
    """Parse a log file and return the URL of every entry (preserving order).

    Uses the project's parser so URLs are URL-decoded / Base64-decoded
    consistently with the production pipeline. Empty / non-HTTP requests
    are returned as '-' so they can be filtered by callers.
    """
    # Local import to avoid pulling parser at package import time
    # (which would force CRS pattern loading before CLI args are parsed).
    from scqlog.parser import parse_log_file

    urls: list[str] = []
    for i, entry in enumerate(parse_log_file(str(log_path))):
        if max_lines is not None and i >= max_lines:
            break
        urls.append(entry.url)
    return urls
