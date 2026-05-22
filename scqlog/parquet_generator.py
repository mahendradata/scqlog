"""Parquet file generator for columnar storage of log data.

Converts parsed log entries into compressed Parquet format optimized
for analytical queries via DuckDB.
"""

from dataclasses import asdict
from pathlib import Path

import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from scqlog.parser import LogEntry, COLUMNS


def entries_to_dataframe(entries: list[LogEntry]) -> pd.DataFrame:
    """
    Convert LogEntry objects to a pandas DataFrame.

    Args:
        entries: List of parsed log entries

    Returns:
        DataFrame with log data, including a `frequency` column counting how
        many rows share each `drain3_template_id`.
    """
    data = [asdict(entry) for entry in entries]
    df = pd.DataFrame(data)
    df['frequency'] = df.groupby('drain3_template_id')['drain3_template_id'].transform('size').astype('int64')
    return df[COLUMNS]


def save_parquet(df: pd.DataFrame, output_path: Path) -> None:
    """
    Save DataFrame to Parquet file with Snappy compression.

    Args:
        df: DataFrame to save
        output_path: Path for the output Parquet file
    """
    table = pa.Table.from_pandas(df, preserve_index=False)
    pq.write_table(
        table,
        output_path,
        compression='snappy',
        use_dictionary=True,
        write_statistics=True
    )
