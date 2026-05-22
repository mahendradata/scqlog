"""Delimiter sensitivity: attack-aware vs default Drain3 tokenization.

The project applies Drain3 with an attack-aware delimiter set (`'`, `"`,
`;`, `<`, `>`, `|`, `` ` ``, `$`, `\\`, `.`, `%`, etc.) so that obfuscation
characters become *cluster boundaries* rather than being absorbed into
template wildcards. This is the actual novel design choice in the
Cluster signal — and it needs an empirical defense.

This script clusters the *same* set of URLs twice — once with default
Drain3 tokenization (whitespace only) and once with the attack-aware
delimiter set — and compares:

  * **Cluster count** and size distribution. More clusters generally
    means finer-grained grouping; very large mega-clusters indicate
    distinct attack patterns being collapsed together.
  * **Cluster purity vs. CRS attack categories.** For each URL, the
    "label" is its argmax-scoring CRS category (over the 8 categories);
    URLs with no non-zero score are unlabeled. Purity is then the
    standard textbook definition::

        purity = (1/N_labeled) * sum_c max_l |c ∩ l|

    Higher purity means each Drain3 cluster is more homogeneous in
    terms of attack type — exactly the property that makes the Cluster
    signal useful as a triage pivot.

Why this matters for Angle 5: the framework's claim is that grouping
attack rows by Drain3 template lets an analyst see "one of each kind"
quickly. If default delimiters give the same purity as attack-aware
delimiters, the design choice is gratuitous; if attack-aware delimiters
score materially higher, this script is the figure that justifies it.

Usage:
    python -m eval.delimiter_sensitivity data/access.log
    python -m eval.delimiter_sensitivity data/access.log --max-lines 50000
"""

from __future__ import annotations

import argparse
import logging
from collections import Counter
from pathlib import Path

from scqlog.attack_detector import ATTACK_TYPES, detect_attacks
from scqlog.config import Config
from eval._common import (
    ATTACK_AWARE_DELIMITERS, cluster_purity, cluster_urls, fmt_table,
    load_urls_from_log, write_csv,
)

logger = logging.getLogger(__name__)


def _argmax_attack_label(url: str) -> str | None:
    """Return the dominant attack category for a URL, or None if no attack.

    Ties are broken by the order in ATTACK_TYPES (i.e. sqli, xss, ...),
    which is deterministic and documented.
    """
    if not url or url == "-":
        return None
    r = detect_attacks(url)
    scores = [(t, getattr(r, f"{t}_score")) for t in ATTACK_TYPES]
    best = max(scores, key=lambda x: x[1])
    return best[0] if best[1] > 0 else None


def _cluster_size_distribution(cluster_ids: list[int]) -> list[tuple[str, int]]:
    """Bucketed cluster-size distribution."""
    sizes = Counter(cluster_ids).values()
    buckets = {"1": 0, "2-10": 0, "11-100": 0, "101-1k": 0, "1k+": 0}
    for s in sizes:
        if s == 1:
            buckets["1"] += 1
        elif s <= 10:
            buckets["2-10"] += 1
        elif s <= 100:
            buckets["11-100"] += 1
        elif s <= 1000:
            buckets["101-1k"] += 1
        else:
            buckets["1k+"] += 1
    return list(buckets.items())


def run(
    log_path: Path,
    output_dir: Path,
    max_lines: int | None = None,
    paranoia_level: int = 1,
) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)

    # Pin PL so eval results are independent of any prior PL state.
    Config.CRS_PARANOIA_LEVEL = paranoia_level
    logger.info(f"Pinned CRS paranoia level to {paranoia_level} for reproducibility")

    logger.info(f"Loading URLs from {log_path}")
    urls = load_urls_from_log(log_path, max_lines=max_lines)
    n = len(urls)
    logger.info(f"Loaded {n:,} entries; computing labels and clustering")

    # Compute labels once (CRS detection is independent of delimiter choice).
    labels = [_argmax_attack_label(u) for u in urls]
    n_labeled = sum(1 for l in labels if l is not None)
    logger.info(f"  labeled URLs (any non-zero CRS score): {n_labeled:,}")

    # Two clusterings on the same input order.
    logger.info("Clustering with default Drain3 delimiters")
    default_cids = cluster_urls(urls, extra_delimiters=None)

    logger.info("Clustering with attack-aware delimiters")
    aware_cids = cluster_urls(urls, extra_delimiters=ATTACK_AWARE_DELIMITERS)

    # Headline metrics.
    default_n_clusters = len(set(default_cids))
    aware_n_clusters = len(set(aware_cids))
    default_purity, _ = cluster_purity(default_cids, labels)
    aware_purity, _ = cluster_purity(aware_cids, labels)

    # Purity is trivially 1.0 on a clustering of all-singletons, so it is
    # only meaningful in conjunction with compression ratio and singleton
    # fraction. We report all three so the trade-off is explicit.
    default_singletons = sum(1 for v in Counter(default_cids).values() if v == 1)
    aware_singletons   = sum(1 for v in Counter(aware_cids).values() if v == 1)
    default_compression = n / default_n_clusters if default_n_clusters else float("nan")
    aware_compression   = n / aware_n_clusters if aware_n_clusters else float("nan")

    # Non-singleton purity: purity restricted to clusters with size >= 2.
    # This is the *meaningful* purity figure — it tells you, of the URLs
    # the clusterer actually grouped together, how often the grouping
    # was attack-homogeneous.
    def nonsingleton_purity(cids: list[int]) -> tuple[float, int]:
        size = Counter(cids)
        keep = {c for c, sz in size.items() if sz >= 2}
        sub_cids = [c for c in cids if c in keep]
        sub_labels = [l for c, l in zip(cids, labels) if c in keep]
        return cluster_purity(sub_cids, sub_labels)

    default_ns_purity, default_ns_n = nonsingleton_purity(default_cids)
    aware_ns_purity, aware_ns_n     = nonsingleton_purity(aware_cids)

    def fmt_pct(x: float) -> str:
        return f"{x * 100:.2f}%" if x == x else "n/a"

    def fmt_f(x: float) -> str:
        return f"{x:.4f}" if x == x else "n/a"

    summary_rows = [
        ["n_urls", n, n],
        ["n_labeled (any score>0)", n_labeled, n_labeled],
        ["n_clusters", default_n_clusters, aware_n_clusters],
        ["compression_ratio (urls/cluster)",
         f"{default_compression:.2f}", f"{aware_compression:.2f}"],
        ["singleton_clusters",
         f"{default_singletons} ({fmt_pct(default_singletons/default_n_clusters)})",
         f"{aware_singletons} ({fmt_pct(aware_singletons/aware_n_clusters)})"],
        ["overall_purity_vs_attack_label",
         fmt_f(default_purity), fmt_f(aware_purity)],
        [f"non_singleton_purity (n={default_ns_n} / {aware_ns_n})",
         fmt_f(default_ns_purity), fmt_f(aware_ns_purity)],
    ]

    # Cluster-size buckets.
    default_buckets = _cluster_size_distribution(default_cids)
    aware_buckets = _cluster_size_distribution(aware_cids)
    bucket_rows = [
        [b, default_buckets[i][1], aware_buckets[i][1]]
        for i, (b, _) in enumerate(default_buckets)
    ]

    csv_path = output_dir / "delimiter_sensitivity.csv"
    write_csv(
        csv_path,
        ["metric", "default_delimiters", "attack_aware_delimiters"],
        summary_rows + [["size_bucket=" + r[0]] + r[1:] for r in bucket_rows],
    )
    logger.info(f"Wrote {csv_path}")

    md_path = output_dir / "delimiter_sensitivity.md"
    with open(md_path, "w", encoding="utf-8") as f:
        f.write("# Drain3 delimiter sensitivity (Cluster signal — design choice)\n\n")
        f.write(f"- Log file: `{log_path}`\n")
        f.write(f"- URLs clustered: {n:,}\n")
        f.write(f"- Labeled URLs: {n_labeled:,} (label = argmax CRS category)\n\n")
        f.write("## Headline metrics\n\n")
        f.write(fmt_table(
            ["metric", "default_delimiters", "attack_aware_delimiters"],
            summary_rows,
        ))
        f.write("\n\n## Cluster-size distribution\n\n")
        f.write(fmt_table(
            ["size_bucket", "default", "attack_aware"],
            bucket_rows,
        ))
        f.write("\n\n## Interpretation\n\n")
        f.write(
            "**Purity alone is not a sufficient metric.** A clusterer "
            "that emits one cluster per URL trivially achieves purity "
            "1.0, because singletons cannot be impure. The useful "
            "question is therefore: does the clusterer compress the "
            "URL space *while preserving purity on the clusters that "
            "actually group multiple URLs together*?\n\n"
        )
        if default_n_clusters > 0 and aware_n_clusters > 0:
            comp_gain = default_n_clusters / aware_n_clusters
            sing_default = default_singletons / default_n_clusters
            sing_aware = aware_singletons / aware_n_clusters
            ns_purity_drop = (default_ns_purity - aware_ns_purity
                              if (default_ns_purity == default_ns_purity
                                  and aware_ns_purity == aware_ns_purity)
                              else float("nan"))
            f.write(
                f"On this input, attack-aware delimiters yield "
                f"**{comp_gain:.2f}× fewer clusters** "
                f"({default_n_clusters} → {aware_n_clusters}) and reduce "
                f"the singleton fraction from {sing_default*100:.1f}% to "
                f"{sing_aware*100:.1f}%, while non-singleton purity "
            )
            if ns_purity_drop != ns_purity_drop:
                f.write("is undefined (no multi-member clusters).\n")
            elif abs(ns_purity_drop) < 0.05:
                f.write(
                    f"changes by only {ns_purity_drop:+.4f} "
                    f"({fmt_f(default_ns_purity)} → "
                    f"{fmt_f(aware_ns_purity)}). "
                    "This is the design-choice payoff: attack-aware "
                    "tokenization concentrates similar attack URLs "
                    "into the same cluster without diluting attack "
                    "homogeneity, making the Cluster signal a more "
                    "useful triage pivot.\n"
                )
            elif ns_purity_drop > 0:
                f.write(
                    f"drops by {ns_purity_drop:.4f}. The compression "
                    "gain comes at a measurable purity cost — the "
                    "trade-off should be evaluated against the analyst "
                    "workflow.\n"
                )
            else:
                f.write(
                    f"actually improves by {-ns_purity_drop:.4f}, a "
                    "rare strict win on both axes.\n"
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
    p.add_argument("--max-lines", type=int, default=None)
    p.add_argument(
        "-pl", "--paranoia-level", type=int, default=1, choices=[1, 2, 3, 4],
        help="CRS paranoia level for the proxy attack labels "
             "(default: %(default)s)",
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
    run(
        args.log_path, args.output_dir,
        max_lines=args.max_lines,
        paranoia_level=args.paranoia_level,
    )


if __name__ == "__main__":
    main()
