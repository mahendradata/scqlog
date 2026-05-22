"""scqlog — command-line entry point.

Processes Apache/NGINX log files and generates:
1. Parquet files (columnar, compressed) with attack detection scores
2. Self-contained HTML dashboards with DuckDB-WASM for interactive SQL filtering

Usage:
    scqlog access.log
    scqlog data/*.log --paranoia-level 2
"""

import argparse
import logging
from pathlib import Path

from scqlog.config import Config
from scqlog.utils import get_version
from scqlog.parser import parse_log_file, COLUMNS
from scqlog.parquet_generator import entries_to_dataframe, save_parquet
from scqlog.html_generator import generate_html

logger = logging.getLogger(__name__)


def process_log_file(log_path: Path) -> None:
    """
    Process a single log file: parse, detect attacks, generate Parquet and HTML.

    Output files are placed in a subdirectory next to the input file, named
    after the input file stem. For example, /logs/access.log produces outputs
    in /logs/access/access.parquet and /logs/access/access.html.

    Args:
        log_path: Path to the input log file
    """
    base_name = log_path.stem
    output_dir = log_path.parent / base_name
    output_dir.mkdir(parents=True, exist_ok=True)

    logger.info(f"Processing: {log_path.name} -> {output_dir}/")

    entries = list(parse_log_file(str(log_path)))
    if not entries:
        logger.warning(f"No valid entries found in {log_path.name}")
        return

    logger.info(f"Parsed {len(entries):,} entries from {log_path.name}")

    logger.info("Creating dataframe")
    df = entries_to_dataframe(entries)

    parquet_path = output_dir / f"{base_name}.parquet"
    html_path = output_dir / f"{base_name}.html"

    logger.info(f"Creating: {parquet_path}")
    save_parquet(df, parquet_path)

    logger.info(f"Creating: {html_path}")
    generate_html(
        parquet_filename=f"{base_name}.parquet",
        title=f"Log Analysis: {base_name}",
        output_path=html_path,
        columns=COLUMNS,
    )


def main() -> None:
    """Entry point for the `scqlog` CLI command."""
    logging.basicConfig(
        level=logging.DEBUG if Config.DEBUG else logging.INFO,
        format="%(asctime)s - %(levelname)s - %(message)s",
    )

    parser = argparse.ArgumentParser(
        prog="scqlog",
        description=(
            "Score, Cluster, Query — convert Apache/NGINX log files into "
            "interactive HTML dashboards with OWASP CRS attack scores and "
            "Drain3 template clusters.\n\n"
            "For each input FILE, outputs are written to a sibling directory:\n"
            "  FILE.log  →  FILE/FILE.parquet  +  FILE/FILE.html\n\n"
            "Open FILE.html over a local HTTP server (not file://) to use the dashboard:\n"
            "  cd FILE && python -m http.server 8000"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "files",
        type=Path,
        nargs="+",
        metavar="FILE",
        help="One or more Apache/NGINX .log files to process",
    )
    parser.add_argument(
        "-pl", "--paranoia-level",
        type=int,
        default=None,
        choices=[1, 2, 3, 4],
        metavar="N",
        help=(
            "OWASP CRS paranoia level — 1 = lowest false-positive rate, "
            "4 = maximum detection sensitivity. "
            "Overrides the CRS_PARANOIA_LEVEL environment variable. "
            "Default: 1."
        ),
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {get_version()}",
    )
    args = parser.parse_args()

    if args.paranoia_level is not None:
        Config.CRS_PARANOIA_LEVEL = args.paranoia_level

    print(f"scqlog v{get_version()}  (CRS paranoia level: {Config.CRS_PARANOIA_LEVEL})")

    log_files: list[Path] = args.files
    logger.info(f"Processing {len(log_files)} file(s)")

    for log_path in log_files:
        if not log_path.is_file():
            logger.error(f"File not found: {log_path}")
            continue
        try:
            process_log_file(log_path)
        except Exception as e:
            logger.error(f"Error processing {log_path.name}: {e}")

    logger.info("Done.")


if __name__ == "__main__":
    main()
