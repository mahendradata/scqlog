"""Run every evaluation in the suite end-to-end and emit a combined report.

Usage:
    python -m eval.run_all data/access.log
    python -m eval.run_all data/access.log --output-dir paper/eval_results
"""

from __future__ import annotations

import argparse
import logging
from pathlib import Path

from eval import paranoia_sensitivity

logger = logging.getLogger(__name__)


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("log_path", type=Path)
    p.add_argument(
        "--output-dir", type=Path, default=None,
        help="Output directory for eval reports. "
             "Default: <log_file_dir>/<log_file_stem>_eval/ "
             "(written next to the input log)",
    )
    p.add_argument("--max-lines", type=int, default=None)
    p.add_argument("--debug", action="store_true")
    args = p.parse_args()

    logging.basicConfig(
        level=logging.DEBUG if args.debug else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    # Default output dir is <log_file_dir>/<log_file_stem>_eval/ so eval
    # artefacts live alongside the log they describe — same convention as
    # scqlog's per-log output dirs.
    if args.output_dir is None:
        args.output_dir = args.log_path.parent / f"{args.log_path.stem}_eval"
    logger.info(f"Writing eval outputs to {args.output_dir}")

    args.output_dir.mkdir(parents=True, exist_ok=True)
    logger.info("=" * 60)
    logger.info("[1/1] Score signal: paranoia-level sensitivity")
    logger.info("=" * 60)
    paranoia_sensitivity.run(args.log_path, args.output_dir, args.max_lines)

    # Write a top-level index pointing at the per-eval reports.
    index = args.output_dir / "README.md"
    with open(index, "w", encoding="utf-8") as f:
        f.write("# Evaluation suite outputs\n\n")
        f.write(f"- Input log: `{args.log_path}`\n\n")
        f.write("| Eval | CSV | Markdown |\n")
        f.write("|------|-----|----------|\n")
        f.write("| Paranoia sensitivity (Score signal) | "
                "`paranoia_sensitivity.csv` | `paranoia_sensitivity.md` |\n")
    logger.info(f"Wrote index: {index}")


if __name__ == "__main__":
    main()
