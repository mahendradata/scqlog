"""Cluster-stability evaluation for the Drain3 Cluster signal.

Drain3 is an *online* template miner: it sees URLs one at a time and
assigns cluster IDs in arrival order. This means the partition can in
principle change with input ordering. For triage to be reliable we want
that ordering effect to be small.

This script measures it empirically:

  1. Load URLs from the input log (preserving original order as run #0).
  2. Generate ``n_runs - 1`` additional shuffles with distinct random seeds.
  3. Cluster each ordering with Drain3 (attack-aware delimiters by default).
  4. Project every clustering back into the *original* row order so they
     are comparable index-by-index.
  5. Compute the Adjusted Rand Index (ARI) between every pair of runs.
  6. Report the pairwise ARI matrix plus mean / min / std across all
     pairs, and the number of distinct clusters per run.

Why this matters for Angle 5: if mean pairwise ARI ≈ 1.0, a Drain3
template ID is a *stable* triage primitive an analyst can rely on. If
ARI is low, the cluster-grouping UI in the dashboard will give different
answers run-to-run, which would undermine the framework's value.

Usage:
    python -m eval.cluster_stability data/access.log
    python -m eval.cluster_stability data/access.log --n-runs 10 --seed 42
"""

from __future__ import annotations

import argparse
import logging
import random
from pathlib import Path

from eval._common import (
    ATTACK_AWARE_DELIMITERS, adjusted_rand_index, cluster_urls,
    fmt_table, load_urls_from_log, write_csv,
)

logger = logging.getLogger(__name__)


def run(
    log_path: Path,
    output_dir: Path,
    n_runs: int = 5,
    seed: int = 0,
    use_default_delimiters: bool = False,
    max_lines: int | None = None,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    if n_runs < 2:
        raise ValueError("n_runs must be >= 2 to compute pairwise ARI")

    delimiters = None if use_default_delimiters else ATTACK_AWARE_DELIMITERS
    logger.info(
        f"Loading URLs from {log_path} "
        f"({'default' if use_default_delimiters else 'attack-aware'} delimiters)"
    )
    urls = load_urls_from_log(log_path, max_lines=max_lines)
    n = len(urls)
    logger.info(f"Loaded {n:,} entries; running {n_runs} clusterings")

    # Run 0 is the original order; the rest are shuffled with distinct seeds.
    cluster_assignments: list[list[int]] = []
    for run_idx in range(n_runs):
        if run_idx == 0:
            indexed_urls = list(enumerate(urls))
        else:
            rng = random.Random(seed + run_idx)
            indexed_urls = list(enumerate(urls))
            rng.shuffle(indexed_urls)

        ordered_urls = [u for _, u in indexed_urls]
        ordered_cids = cluster_urls(ordered_urls, delimiters)

        # Re-project back into original order so the position-i entry
        # always refers to the same URL across runs.
        original_cids = [0] * n
        for pos, (orig_i, _) in enumerate(indexed_urls):
            original_cids[orig_i] = ordered_cids[pos]
        cluster_assignments.append(original_cids)
        logger.info(
            f"  run {run_idx}: "
            f"{len(set(original_cids))} unique clusters"
        )

    # Pairwise ARI.
    pairwise_rows: list[list] = []
    aris: list[float] = []
    for i in range(n_runs):
        for j in range(i + 1, n_runs):
            ari = adjusted_rand_index(cluster_assignments[i], cluster_assignments[j])
            pairwise_rows.append([i, j, f"{ari:.6f}"])
            aris.append(ari)

    cluster_counts = [len(set(c)) for c in cluster_assignments]

    csv_path = output_dir / "cluster_stability_pairwise_ari.csv"
    write_csv(csv_path, ["run_a", "run_b", "ari"], pairwise_rows)
    logger.info(f"Wrote {csv_path}")

    summary_rows = [
        ["n_runs", n_runs],
        ["mean_ari", f"{sum(aris) / len(aris):.6f}"],
        ["min_ari", f"{min(aris):.6f}"],
        ["max_ari", f"{max(aris):.6f}"],
        ["mean_clusters_per_run", f"{sum(cluster_counts) / len(cluster_counts):.2f}"],
        ["min_clusters_per_run", min(cluster_counts)],
        ["max_clusters_per_run", max(cluster_counts)],
        ["delimiter_set", "default" if use_default_delimiters else "attack_aware"],
    ]
    md_path = output_dir / "cluster_stability.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Drain3 cluster stability (Cluster signal)\n\n")
        f.write(f"- Log file: `{log_path}`\n")
        f.write(f"- URLs clustered per run: {n:,}\n\n")
        f.write("## Summary\n\n")
        f.write(fmt_table(["metric", "value"], summary_rows))
        f.write("\n\n## Pairwise ARI\n\n")
        f.write(fmt_table(["run_a", "run_b", "ari"], pairwise_rows))
        f.write("\n\n## Interpretation\n\n")
        f.write(
            "Adjusted Rand Index is permutation-invariant on cluster "
            "labels: two runs that group the *same* URLs together "
            "score 1.0 even if the integer cluster IDs differ. Values "
            "near 1.0 indicate Drain3 produces ordering-robust "
            "clusters; values below ~0.8 suggest the Cluster signal "
            "should be treated as run-specific rather than canonical.\n"
        )
    logger.info(f"Wrote {md_path}")


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("log_path", type=Path)
    p.add_argument(
        "--output-dir", type=Path, default=None,
        help="Output directory for CSV + markdown reports "
             "(default: <log_dir>/<log_stem>_eval/)",
    )
    p.add_argument("--n-runs", type=int, default=5,
                   help="Number of clusterings to compare (default: %(default)s)")
    p.add_argument("--seed", type=int, default=0,
                   help="Base RNG seed; run k uses seed+k (default: %(default)s)")
    p.add_argument(
        "--default-delimiters", action="store_true",
        help="Use Drain3's default tokenization (whitespace only) instead "
             "of the attack-aware delimiter set",
    )
    p.add_argument("--max-lines", type=int, default=None)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )
    if args.output_dir is None:
        args.output_dir = args.log_path.parent / f"{args.log_path.stem}_eval"
    logger.info(f"Writing eval outputs to {args.output_dir}")
    run(
        args.log_path, args.output_dir,
        n_runs=args.n_runs, seed=args.seed,
        use_default_delimiters=args.default_delimiters,
        max_lines=args.max_lines,
    )


if __name__ == "__main__":
    main()
