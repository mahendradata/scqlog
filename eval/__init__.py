"""Evaluation suite for the Score signal of the three-signal framework.

Each module measures one property of the Score signal:

- ``paranoia_sensitivity`` — how the per-category CRS match-count distribution
  changes across paranoia levels 1–4: are higher PLs monotonically broader?

Run standalone with ``python -m eval.paranoia_sensitivity --help``, or run
the full suite with ``python -m eval.run_all``.
"""
