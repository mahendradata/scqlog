"""Paranoia-level sensitivity sweep for the Score signal.

For each CRS paranoia level (1..4) and each of the eight attack categories,
report on a given log file:

  * n_rules        — number of CRS rules active for that category at that PL
  * n_flagged      — rows with score > 0
  * pct_flagged    — fraction of (URL-bearing) rows flagged
  * mean_score     — mean of (score) over all rows, including zeros
  * mean_pos       — mean of (score) over only flagged rows
  * p95_score      — 95th-percentile score over flagged rows
  * max_score      — maximum observed score

Outputs a CSV (one row per (paranoia_level, category)) and a markdown
summary suitable for inclusion in the paper.

Why this matters for Angle 5: the Score signal's tunability — the claim
that an analyst can dial sensitivity from few false positives to maximum
recall — only holds if higher PL actually surfaces strictly more rows.
This script makes that monotonicity (or lack thereof) measurable.

Usage:
    python -m eval.paranoia_sensitivity data/access.log
    python -m eval.paranoia_sensitivity data/access.log --output-dir eval_results/
    python -m eval.paranoia_sensitivity data/access.log --max-lines 50000
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

import numpy as np

from scqlog.attack_detector import (
    ATTACK_TYPES, ATTACK_COLUMNS, detect_attacks, get_patterns,
)
from scqlog.config import Config
from eval._common import fmt_table, percentile, write_csv, load_urls_from_log

logger = logging.getLogger(__name__)

PARANOIA_LEVELS = [1, 2, 3, 4]


def _score_array(urls: list[str]) -> np.ndarray:
    """Return an (N, 8) int array of scores for the eight attack categories."""
    out = np.zeros((len(urls), len(ATTACK_TYPES)), dtype=np.int32)
    for i, u in enumerate(urls):
        r = detect_attacks(u)
        for j, t in enumerate(ATTACK_TYPES):
            out[i, j] = getattr(r, f"{t}_score")
    return out


def run(log_path: Path, output_dir: Path, max_lines: int | None = None) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Loading URLs from {log_path}")
    urls = load_urls_from_log(log_path, max_lines=max_lines)
    n_total = len(urls)
    n_with_url = sum(1 for u in urls if u and u != "-")
    logger.info(f"Loaded {n_total:,} entries ({n_with_url:,} with URLs)")

    rows: list[list] = []
    for pl in PARANOIA_LEVELS:
        Config.CRS_PARANOIA_LEVEL = pl
        # Force pattern reload at this PL so the rule-count column is correct.
        patterns = get_patterns()
        logger.info(f"PL={pl}: scoring {n_total:,} URLs")

        scores = _score_array(urls)  # shape (N, 8)

        for j, cat in enumerate(ATTACK_TYPES):
            col = scores[:, j]
            pos = col[col > 0]
            n_flagged = int(pos.size)
            pct_flagged = (n_flagged / n_with_url) if n_with_url else 0.0
            rows.append([
                pl,
                cat,
                len(patterns[cat]),                     # n_rules
                n_flagged,                              # n_flagged
                f"{pct_flagged * 100:.3f}",             # pct_flagged (%)
                f"{col.mean():.4f}" if col.size else "0",      # mean_score
                f"{pos.mean():.4f}" if n_flagged else "0",     # mean_pos
                f"{percentile(pos, 95):.2f}" if n_flagged else "0",
                int(col.max()) if col.size else 0,
            ])

    header = [
        "paranoia_level", "category", "n_rules", "n_flagged",
        "pct_flagged_%", "mean_score", "mean_score_when_flagged",
        "p95_score_when_flagged", "max_score",
    ]
    csv_path = output_dir / "paranoia_sensitivity.csv"
    write_csv(csv_path, header, rows)
    logger.info(f"Wrote {csv_path}")

    md_path = output_dir / "paranoia_sensitivity.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write(f"# Paranoia-level sensitivity (Score signal)\n\n")
        f.write(f"- Log file: `{log_path}`\n")
        f.write(f"- Total entries: {n_total:,}\n")
        f.write(f"- Entries with a URL: {n_with_url:,}\n\n")
        f.write(fmt_table(header, rows))
        f.write("\n\n## How to read\n\n")
        f.write(
            "* **n_rules** is the number of OWASP CRS @rx patterns active "
            "for the category at that paranoia level. It should be "
            "monotonically non-decreasing in PL.\n"
            "* **pct_flagged** is the fraction of URL-bearing rows with a "
            "non-zero score. If raising PL from 1→4 produces a large jump "
            "in pct_flagged with no extra true positives in the labeled "
            "set, that's a tunable false-positive cost the analyst can "
            "trade off.\n"
            "* **mean_score_when_flagged** captures the *strength* of "
            "the signal, not just its breadth — a category with low "
            "pct_flagged but high mean_score is a high-confidence "
            "detector.\n"
        )
    logger.info(f"Wrote {md_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("log_path", type=Path, help="Input .log file")
    p.add_argument(
        "--output-dir", type=Path, default=None,
        help="Output directory for CSV + markdown reports "
             "(default: <log_dir>/<log_stem>_eval/)",
    )
    p.add_argument(
        "--max-lines", type=int, default=None,
        help="Cap on lines parsed (useful for quick iteration)",
    )
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    if args.output_dir is None:
        args.output_dir = args.log_path.parent / f"{args.log_path.stem}_eval"
    logger.info(f"Writing eval outputs to {args.output_dir}")
    run(args.log_path, args.output_dir, args.max_lines)


if __name__ == "__main__":
    main()
