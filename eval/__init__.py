"""Evaluation suite for the three-signal framework (Score, Cluster, Query).

Each module measures one property of one signal:

- ``paranoia_sensitivity`` — Score signal: how the per-category match-count
  distribution changes across CRS paranoia levels 1–4.
- ``cluster_stability``    — Cluster signal: agreement of Drain3 partitions
  under shuffled input order, measured with the Adjusted Rand Index (ARI).
- ``delimiter_sensitivity`` — Cluster signal (design choice): comparing
  default Drain3 tokenization to the attack-aware delimiter set used in
  ``scqlog/parser.py``, scored by attack-category purity.

Run any module standalone with ``python -m eval.<module> --help``, or run
the full suite with ``python -m eval.run_all``.
"""
