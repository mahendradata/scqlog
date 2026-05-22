"""Shared helpers for the evaluation suite.

Kept dependency-light: only stdlib + numpy + the Drain3 dependency the
main pipeline already pulls in.
"""

from __future__ import annotations

import math
from collections import Counter
from pathlib import Path
from typing import Iterable

import numpy as np

from drain3 import TemplateMiner
from drain3.template_miner_config import TemplateMinerConfig


# Attack-aware delimiters as used in scqlog/parser.py.
# Kept here verbatim so the eval can vary it without touching the parser.
ATTACK_AWARE_DELIMITERS: list[str] = [
    # URL structure
    "/", "?", "&", "=", ":", "#",
    # SQLi — string delimiters, statement terminator, function calls, list separator
    "'", '"', ";", "(", ")", ",",
    # XSS — HTML tag brackets
    "<", ">",
    # Command injection — pipe, backtick, dollar (command substitution)
    "|", "`", "$", "\\",
    # Path traversal / LFI — dot and backslash
    ".", "\\",
    # URL encoding, misc attack characters
    "%", "@", "!", "+", "~", "^", "[", "]", "{", "}",
]


def make_template_miner(extra_delimiters: list[str] | None = None) -> TemplateMiner:
    """Build a fresh Drain3 TemplateMiner with the given extra delimiters.

    Args:
        extra_delimiters: Characters Drain3 should treat as token separators
            in addition to whitespace. Pass None or [] for default Drain3
            tokenization (whitespace only).

    Returns:
        A new TemplateMiner instance. Each call yields an independent
        clusterer with its own state.
    """
    cfg = TemplateMinerConfig()
    cfg.profiling_enabled = False
    if extra_delimiters:
        cfg.drain_extra_delimiters = list(extra_delimiters)
    return TemplateMiner(persistence_handler=None, config=cfg)


def cluster_urls(urls: Iterable[str], extra_delimiters: list[str] | None) -> list[int]:
    """Cluster a sequence of URLs with Drain3 and return the cluster ID per URL.

    Order matters: Drain3 is online and assigns templates in arrival order.

    Args:
        urls: URLs to cluster.
        extra_delimiters: As in ``make_template_miner``.

    Returns:
        A list of integer cluster IDs, parallel to the input order.
    """
    miner = make_template_miner(extra_delimiters)
    out: list[int] = []
    for u in urls:
        if not u or u == "-":
            out.append(0)
            continue
        result = miner.add_log_message(u)
        out.append(int(result["cluster_id"]))
    return out


def adjusted_rand_index(labels_a: list[int], labels_b: list[int]) -> float:
    """Adjusted Rand Index between two clusterings of the same N items.

    ARI = 1 means identical partitions (up to label permutation),
    0 means agreement no better than chance, and can go slightly negative
    for worse-than-chance agreements.

    Implemented from scratch (no scikit-learn dependency). For two
    clusterings X (with clusters X_i) and Y (with clusters Y_j):

        index           = sum_ij  C(n_ij, 2)
        expected_index  = (sum_i C(a_i, 2) * sum_j C(b_j, 2)) / C(N, 2)
        max_index       = (sum_i C(a_i, 2) + sum_j C(b_j, 2)) / 2
        ARI             = (index - expected_index) / (max_index - expected_index)

    where n_ij = |X_i ∩ Y_j|, a_i = |X_i|, b_j = |Y_j|.
    """
    if len(labels_a) != len(labels_b):
        raise ValueError("clusterings must be the same length")
    n = len(labels_a)
    if n < 2:
        return 1.0

    # Build contingency table without an O(n_clusters^2) dense matrix.
    table: dict[tuple[int, int], int] = {}
    a_counts: Counter[int] = Counter()
    b_counts: Counter[int] = Counter()
    for la, lb in zip(labels_a, labels_b):
        table[(la, lb)] = table.get((la, lb), 0) + 1
        a_counts[la] += 1
        b_counts[lb] += 1

    def comb2(x: int) -> int:
        return x * (x - 1) // 2

    sum_nij = sum(comb2(c) for c in table.values())
    sum_a   = sum(comb2(c) for c in a_counts.values())
    sum_b   = sum(comb2(c) for c in b_counts.values())
    total   = comb2(n)

    if total == 0:
        return 1.0
    expected = (sum_a * sum_b) / total
    max_idx = (sum_a + sum_b) / 2
    denom = max_idx - expected
    if denom == 0:
        # Both clusterings are trivial (all-in-one or all-singleton).
        return 1.0 if sum_nij == expected else 0.0
    return (sum_nij - expected) / denom


def cluster_purity(cluster_ids: list[int], labels: list[int | str | None]) -> tuple[float, int]:
    """Standard cluster purity over labeled items.

    Items with label=None are excluded (treated as unlabeled). Returns
    a tuple (purity, n_labeled). Purity is in [0, 1]; 1.0 means every
    cluster is internally homogeneous w.r.t. the label.

        purity = (1/N_labeled) * sum_c max_l |c ∩ l|

    where the sum is over clusters c and the max is over labels l.
    """
    by_cluster: dict[int, Counter] = {}
    n_labeled = 0
    for cid, lab in zip(cluster_ids, labels):
        if lab is None:
            continue
        n_labeled += 1
        by_cluster.setdefault(cid, Counter())[lab] += 1

    if n_labeled == 0:
        return float("nan"), 0
    correct = sum(max(ctr.values()) for ctr in by_cluster.values())
    return correct / n_labeled, n_labeled


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
