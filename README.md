# scqlog — Score, Cluster, Query

**scqlog** converts Apache/NGINX server log files into interactive HTML dashboards
with built-in security attack detection.
It implements a three-signal framework:

| Signal | Technology | What it adds |
|--------|-----------|--------------|
| **Score** | OWASP CRS rules (PL 1–4) | Integer match count per attack category |
| **Cluster** | Drain3 template mining | Stable cluster ID grouping structurally similar URLs |
| **Query** | DuckDB-WASM + Parquet | In-browser SQL over millions of rows, zero back-end |

Source code: <https://github.com/mahendradata/scqlog>

---

## How It Works

The program is a two-stage pipeline: a Python ingestion stage that runs once per
log file, and a browser-side analysis stage that runs each time the dashboard is opened.

### Stage 1 — Ingestion (Python, one-shot)

For every input `.log` file, `scqlog` runs the following pipeline:

1. **Line-by-line parsing** (`scqlog/parser.py`) — Each line is matched against two
   regexes in order:
   - `LOG_PATTERN` — the standard Apache/NGINX combined format.
   - `LOG_PATTERN_RAW_REQUEST` — a fallback that captures empty (`""`) or non-HTTP
     request payloads (e.g. `\x13BitTorrent protocol...`) into the `url` field with
     `method` and `protocol` set to `-`.

   Lines that match neither become a fallback `LogEntry` with all fields set to `-`,
   so every input line produces exactly one output row (the schema stays consistent
   and nothing is silently dropped).

2. **Decoding** (`decode_value`) — The `url` and `referrer` fields are URL-decoded;
   if the decoded string looks like Base64 (`is_likely_base64`), a Base64 decode is
   also attempted. This makes obfuscated attack payloads readable to both the rule
   detectors and the human analyst.

3. **Template clustering** (`drain3`) — The decoded URL is fed into a Drain3
   `TemplateMiner` configured with attack-aware delimiters (`'`, `"`, `;`, `<`, `>`,
   `|`, `` ` ``, `$`, `\`, etc.). Drain3 returns a stable `cluster_id` and a
   `template_mined` string, so structurally similar requests (e.g. thousands of
   `/api/v1/users/<*>` hits) collapse into a single template you can group by in
   DuckDB.

4. **Attack detection** (`scqlog/attack_detector.py`) — The decoded URL is scanned
   against eight attack categories. Patterns are loaded exclusively from OWASP CRS
   rule files in `scqlog/crs/` at startup (filtered by `CRS_PARANOIA_LEVEL`); there
   is no built-in regex fallback, so a category whose CRS file is missing produces a
   score of 0 and emits a warning at startup. Each `*_score` column stores the
   **number of CRS rules that matched** (0 means clean), which is more useful than a
   boolean — a request matching 8 SQLi rules is more confidently malicious than one
   matching 1.

5. **Columnar output** (`scqlog/parquet_generator.py`) — `LogEntry` objects are
   converted to a pandas DataFrame (with a `frequency` column added via groupby) and
   written as Parquet with Snappy compression, dictionary encoding, and column
   statistics. Statistics enable DuckDB's predicate pushdown so the WASM engine can
   skip whole row groups that can't satisfy a `WHERE` clause.

6. **Self-contained dashboard** (`scqlog/html_generator.py`) — A single HTML file is
   generated per log. It embeds the column list and the Parquet filename; on page
   load, DuckDB WASM fetches the Parquet over HTTP and registers it as a table.

For an input `data/access.log`, the outputs are placed in a sibling directory:
`data/access/access.parquet` and `data/access/access.html`.

### Stage 2 — Analysis (Browser, interactive)

The HTML dashboard is fully client-side. When opened:

1. DuckDB WASM is loaded and the Parquet file is fetched from the same directory
   (this is why a static HTTP server is required — `file://` won't allow the fetch).
2. Every interaction (typing a `WHERE` clause, sorting, paginating, toggling distinct
   mode, exporting CSV) compiles to a SQL query that runs against the Parquet file in
   the browser.
3. Pagination uses `LIMIT`/`OFFSET` rather than loading the full dataset, so files
   with millions of rows stay responsive without crashing the browser tab.
4. CSV export re-runs the current query and serialises the visible columns only.

Because the analysis stage runs entirely in the browser, the generated HTML + Parquet
pair is portable: move them to any static host (S3, GitHub Pages, an internal share)
and the dashboard works without a Python backend.

---

## Features

- **Log Parsing**: Parses Apache/NGINX combined log format with URL-decoding and Base64 detection
- **Attack Detection**: 8 attack categories backed by **OWASP CRS** rules — SQL injection, XSS, path traversal, command injection, RCE, LFI, RFI, webshell probing. Detection results are integer match counts (`*_score`), not booleans
- **Configurable Paranoia**: `CRS_PARANOIA_LEVEL` (or `-pl` flag) selects how aggressively CRS rules fire (1–4)
- **Drain3 Template Clustering**: Each request is assigned a cluster ID and mined template, so structurally similar URLs collapse into one analysable group
- **Template Frequency**: A `frequency` column counts how many rows share each `drain3_template_id`, making it easy to spot common request shapes vs. one-off requests
- **Columnar Storage**: Outputs compressed Parquet (Snappy + dictionary encoding + statistics) for fast filtering
- **Interactive Dashboard**: Browser-based visualisation with DuckDB WASM for SQL filtering
- **Memory-Safe Pagination**: Uses `LIMIT/OFFSET` queries to handle large datasets without browser crashes
- **WHERE Clause Filtering**: Custom SQL WHERE expressions with real-time validation
- **Distinct Row Filter**: Toggle to dedupe results by the currently visible columns (e.g. hide everything except `url` for a list of unique URLs)
- **CSV Export**: Export filtered results respecting column visibility settings
- **Column Controls**: Show/hide columns and resize column widths
- **Non-HTTP Request Handling**: Gracefully handles empty requests and binary protocol data (e.g., BitTorrent)

---

## Requirements

- **Python**: 3.11+
- **Dependencies** (declared in `pyproject.toml`, pinned in `requirements.txt`):
  - `pandas==3.0.2`
  - `pyarrow==24.0.0`
  - `drain3==0.9.11` — log template clustering
- **Docker**: 20.10+ (optional, for containerised deployment)
- **Browser**: Modern browser with WebAssembly support (Chrome, Firefox, Safari, Edge)

---

## Installation

### From GitHub (recommended)

```bash
git clone https://github.com/mahendradata/scqlog
cd scqlog
pip install -e .
```

This installs the `scqlog` command into your environment.

### From PyPI (once published)

```bash
pip install scqlog
```

### Using Docker

```bash
git clone https://github.com/mahendradata/scqlog
cd scqlog
docker compose build
```

---

## Usage

`scqlog` takes one or more `.log` files as positional arguments. For each input
`path/to/access.log`, outputs are written to a sibling directory named after the file
stem: `path/to/access/access.parquet` and `path/to/access/access.html`.

### Option A: pip install (recommended)

```bash
# Process one or more log files
scqlog data/access.log
scqlog data/*.log

# Increase OWASP CRS paranoia level (1=fewest false positives, 4=max detection)
scqlog -pl 2 data/access.log
scqlog --paranoia-level 4 data/access.log

# Show version
scqlog --version

# Serve the dashboard (required — WASM cannot load Parquet over file://)
cd data/access
python -m http.server 8000
# Open http://localhost:8000/access.html
```

**CLI flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-pl`, `--paranoia-level {1,2,3,4}` | `CRS_PARANOIA_LEVEL` env var, else `1` | OWASP CRS paranoia level — higher detects more attacks but increases false-positive rate |
| `--version` | — | Print version and exit |

### Option B: Docker Compose

```bash
# Place .log files in data/ (bind-mounted into the container at /app/data)
cp your-access.log data/

# Build and run — processes data/*.log then starts HTTP server on :8000
docker compose up --build

# Open http://localhost:8000/your-access/your-access.html
```

The container's `entrypoint.sh` runs `scqlog data/*.log` and then serves `/app/data`
on port 8000. Outputs are written next to each input as
`/app/data/<basename>/<basename>.{parquet,html}`, and because `./data` is
bind-mounted from the host, the generated files also appear in your local `data/`
directory.

---

## Project Structure

```
scqlog/                          # Root of the repository
├── pyproject.toml               # Package metadata + `scqlog` console-script entry point
├── requirements.txt             # Pinned dependency versions
├── Dockerfile                   # Container definition
├── docker-compose.yml           # Multi-container orchestration
├── entrypoint.sh                # Docker entrypoint (runs `scqlog data/*.log`)
├── data/                        # Place .log files here; outputs written next to each input
│                                #   as <basename>/<basename>.{parquet,html}
├── scqlog/                      # Main Python package
│   ├── __init__.py
│   ├── cli.py                   # `scqlog` CLI entry point (argparse + pipeline orchestration)
│   ├── config.py                # Configuration from environment variables
│   ├── parser.py                # Log parser — dual-format regex + Drain3 templating
│   ├── attack_detector.py       # Attack detection (OWASP CRS rules only, lazy load)
│   ├── crs_loader.py            # Loads @rx patterns from OWASP CRS .conf files
│   ├── crs/                     # OWASP CRS rule files (.conf)
│   ├── parquet_generator.py     # DataFrame → Parquet conversion (adds `frequency` column)
│   ├── html_generator.py        # Interactive dashboard generator (DuckDB WASM)
│   └── utils.py                 # Utility functions
└── eval/                        # Evaluation suite for the three-signal framework
    ├── __init__.py
    ├── _common.py               # Shared helpers (ARI, purity, TemplateMiner factory)
    ├── paranoia_sensitivity.py  # Score signal: PL=1..4 sweep
    ├── cluster_stability.py     # Cluster signal: ARI under shuffled input
    ├── delimiter_sensitivity.py # Cluster design: attack-aware vs default delimiters
    └── run_all.py               # Run all three evals and write an index README
```

---

## API / Functions Reference

### scqlog/cli.py

| Function | Description |
|----------|-------------|
| `main()` | Entry point for the `scqlog` CLI command; parses args and calls `process_log_file` for each input |
| `process_log_file(log_path)` | Runs the full pipeline for one log file; writes outputs to `<log_path.parent>/<log_path.stem>/` |

### scqlog/parser.py

| Function/Class | Description |
|----------------|-------------|
| `LogEntry` | Dataclass representing a parsed log entry with 23 fields (13 core + 2 Drain3 + 8 attack-score) |
| `COLUMNS` | Module-level list of `LogEntry` field names, with `frequency` inserted after `drain3_template`. Used as the DataFrame/Parquet schema |
| `parse_log_file(filepath)` | Generator yielding a `LogEntry` for every line in the file |
| `parse_line(line, line_number)` | Parses a single log line; tries `LOG_PATTERN` then `LOG_PATTERN_RAW_REQUEST`, falls back to a `'-'`-filled entry |
| `decode_value(value)` | URL-decodes and optionally Base64-decodes a string |
| `is_likely_base64(s)` | Checks if a string appears to be Base64-encoded |

### scqlog/attack_detector.py

| Function/Class | Description |
|----------------|-------------|
| `AttackDetectionResult` | Dataclass; each `*_score` field is the **number of CRS rules matched** (`int`), `0` = none |
| `detect_attacks(url)` | Returns an `AttackDetectionResult` for the given URL |
| `get_patterns()` | Returns the active per-category `dict[str, list[re.Pattern]]`; lazily built and cached per paranoia level, rebuilt automatically if `Config.CRS_PARANOIA_LEVEL` changes |
| `ATTACK_TYPES` / `ATTACK_COLUMNS` | Lists of the eight attack category keys / column names |

### scqlog/crs_loader.py

| Function | Description |
|----------|-------------|
| `build_patterns(conf_files, max_paranoia=1)` | Parses one or more OWASP CRS `.conf` files, extracts each `@rx` pattern, filters by paranoia level, returns a list of compiled `re.Pattern` (one per CRS rule) |

### scqlog/parquet_generator.py

| Function | Description |
|----------|-------------|
| `entries_to_dataframe(entries)` | Converts a list of `LogEntry` to a pandas DataFrame, computes the `frequency` column (count of rows sharing each `drain3_template_id`), and orders columns per `COLUMNS` |
| `save_parquet(df, output_path)` | Saves DataFrame to Parquet with Snappy compression, dictionary encoding, and column statistics |

### scqlog/html_generator.py

| Function | Description |
|----------|-------------|
| `generate_html(parquet_filename, title, output_path, columns)` | Generates a self-contained HTML dashboard (DuckDB WASM) at `output_path`, referencing `parquet_filename` (relative path) |

### scqlog/config.py

| Attribute | Description |
|-----------|-------------|
| `Config.APP_NAME` | App name (env: `APP_NAME`, default: `scqlog`) |
| `Config.VERSION` | Application version string (currently `2.0.0`) |
| `Config.DEBUG` | Enable debug logging (env: `DEBUG`) |
| `Config.CRS_PARANOIA_LEVEL` | OWASP CRS paranoia level 1–4 (env: `CRS_PARANOIA_LEVEL`, default `1`) |

---

## Configuration

### Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `DEBUG` | `false` | Enable debug logging |
| `APP_NAME` | `scqlog` | Application name displayed in logs |
| `CRS_PARANOIA_LEVEL` | `1` | OWASP CRS paranoia level (1–4); higher detects more attacks but increases false positives |

Input and output paths are not configured via environment variables — pass log files
directly to `scqlog` as positional arguments (or use the `-pl` flag for paranoia level).

### Supported Log Format

**Apache/NGINX Combined Format** (standard HTTP requests):
```
host ident authuser [timestamp] "method url protocol" status size "referrer" "user-agent"
```

Example:
```
192.168.1.1 - - [01/Jan/2024:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "-" "Mozilla/5.0"
```

**Non-HTTP Requests** (empty or binary data):
```
157.230.42.58 - - [29/Dec/2025:13:58:22 +0700] "" 400 0 "-" "-"
74.82.60.74 - - [22/Jan/2019:08:27:26 +0330] "\x13BitTorrent protocol..." 400 166 "-" "-"
```

### Output Columns

**Core log fields:**

| Column | Type | Description |
|--------|------|-------------|
| `line_number` | int | Original line number in log file |
| `host` | str | Client IP address |
| `ident` | str | Client identity (usually `-`) |
| `authuser` | str | Authenticated user (usually `-`) |
| `timestamp` | str | Request timestamp |
| `method` | str | HTTP method (GET, POST, etc.) or `-` for non-HTTP |
| `url` | str | Requested URL (URL-decoded, optionally Base64-decoded) or raw request content |
| `protocol` | str | HTTP protocol version or `-` for non-HTTP |
| `status` | str | HTTP response status code |
| `size` | str | Response size in bytes |
| `referrer` | str | Referrer URL (URL-decoded) |
| `user_agent` | str | Client user agent string |
| `extra` | str | Anything trailing the standard fields |

**Drain3 log-template clustering:**

| Column | Type | Description |
|--------|------|-------------|
| `drain3_template_id` | int | Cluster ID assigned by Drain3 to structurally similar URLs (`0` = no URL) |
| `drain3_template` | str | Mined template string with variable parts replaced by `<*>` |
| `frequency` | int | Number of rows in this log file sharing the same `drain3_template_id`. High values flag common request shapes; `frequency = 1` flags one-off requests |

**Attack detection columns:**

Each column is an **integer count of CRS rules that matched** (`0` = no match).
A higher count generally indicates higher confidence the request is malicious.

| Column | Attack Type | CRS file (in `scqlog/crs/`) |
|--------|-------------|------------------------------|
| `sqli_score` | SQL Injection (UNION/SELECT, OR 1=1, sleep(), etc.) | `REQUEST-942-APPLICATION-ATTACK-SQLI.conf` |
| `xss_score` | Cross-Site Scripting (`<script>`, event handlers, javascript:) | `REQUEST-941-APPLICATION-ATTACK-XSS.conf` |
| `path_traversal_score` | Path Traversal (`../`, URL-encoded variants) | `REQUEST-930-APPLICATION-ATTACK-LFI.conf` |
| `cmd_injection_score` | Command Injection (`;`, `\|`, `&&`, command substitution) | `REQUEST-932-APPLICATION-ATTACK-RCE.conf` |
| `rce_score` | Remote Code Execution (PHP streams, system(), exec()) | `REQUEST-932-…-RCE.conf` + `REQUEST-933-…-PHP.conf` |
| `lfi_score` | Local File Inclusion (`/etc/passwd`, `/proc/self`) | `REQUEST-930-APPLICATION-ATTACK-LFI.conf` |
| `rfi_score` | Remote File Inclusion (remote PHP/ASP/JSP files) | `REQUEST-931-APPLICATION-ATTACK-RFI.conf` |
| `webshell_score` | WebShell Probing (c99, r57, `cmd=` parameters) | `REQUEST-933-APPLICATION-ATTACK-PHP.conf` |

Patterns come exclusively from OWASP CRS `.conf` files in `scqlog/crs/` (filtered by
`CRS_PARANOIA_LEVEL`). There is no regex fallback — if a CRS file is missing, the
corresponding category will always score `0` and a warning is logged at startup.

---

## Examples

### Example WHERE Queries in Dashboard

```sql
-- Find all error responses
status >= 400

-- Find potential SQL injection attempts (any rule matched)
sqli_score > 0

-- High-confidence SQL injection (multiple rules matched)
sqli_score >= 3

-- Find requests from a specific IP
host = '192.168.1.1'

-- Find large responses (>10KB)
CAST(size AS INTEGER) > 10000

-- 404s that also look like webshell probes
status = 404 AND webshell_score > 0

-- Filter by timestamp pattern
timestamp LIKE '%Jan/2024%'

-- Find POST requests to admin pages
method = 'POST' AND url LIKE '%admin%'

-- Find all detected attacks (any category)
sqli_score > 0 OR xss_score > 0 OR path_traversal_score > 0 OR cmd_injection_score > 0
   OR rce_score > 0 OR lfi_score > 0 OR rfi_score > 0 OR webshell_score > 0

-- Most common request shapes (high template frequency)
frequency >= 100

-- One-off requests (unique template, often suspicious)
frequency = 1

-- Drill into one specific Drain3 cluster
drain3_template_id = 42

-- Show only non-HTTP / malformed requests
method = '-'
```

### Dashboard Features

1. **WHERE Filter Panel**: Enter custom DuckDB WHERE clauses with real-time validation
2. **Example Queries**: Click pre-built filters for common analysis tasks
3. **Column Names**: Click column names to insert them into your query
4. **Distinct Rows**: Checkbox to dedupe results by the currently visible columns (toggling visibility re-runs the query)
5. **Column Visibility**: Toggle individual columns with checkboxes
6. **Column Resizing**: Drag column borders to adjust widths
7. **Sorting**: Click column headers to sort ascending/descending
8. **Pagination**: Choose 10, 25, 50, or 100 rows per page
9. **CSV Export**: Download filtered data (respects column visibility)
10. **Keyboard Shortcut**: Press `Ctrl+Enter` to apply WHERE filter

---

## Evaluation

The `eval/` package quantifies the Score and Cluster signals. Every evaluation runs
against any `.log` file the pipeline can already parse — no labelled ground-truth
dataset is required. CSV + markdown reports are written to `eval_results/`
(configurable via `--output-dir`).

### Running an eval

```bash
# All three at once (writes a README.md index in the output dir)
python -m eval.run_all data/access.log

# Or one at a time
python -m eval.paranoia_sensitivity   data/access.log
python -m eval.cluster_stability      data/access.log --n-runs 10
python -m eval.delimiter_sensitivity  data/access.log -pl 2

# Cap the number of lines parsed for quick iteration
python -m eval.run_all data/access.log --max-lines 50000
```

### What each eval measures

| Eval | Signal | What it answers |
|------|--------|-----------------|
| `paranoia_sensitivity` | Score | How does the per-category score distribution change across CRS paranoia levels 1–4? Is the PL dial monotone in detection breadth? |
| `cluster_stability` | Cluster | Drain3 is online and order-sensitive. Does the partition stay stable under shuffled input? Reported as pairwise Adjusted Rand Index (ARI) across N runs. |
| `delimiter_sensitivity` | Cluster (design choice) | Does the attack-aware delimiter set compress the cluster space versus default Drain3 tokenisation *while preserving non-singleton purity* against the dominant CRS attack category? |

### Why these three

The framework's claim is that combining (a) tunable rule-count scoring, (b)
ordering-stable templates, and (c) ad-hoc SQL gives an analyst a useful triage
workflow. Each eval falsifies one part of that claim if it fails:

- If `paranoia_sensitivity` shows non-monotone behaviour, the Score dial is not the tunable knob it claims to be.
- If `cluster_stability`'s mean ARI is low (≪ 1.0), the Cluster signal is run-specific noise rather than a triage primitive.
- If `delimiter_sensitivity` shows attack-aware delimiters give the same compression and purity as the default, the design choice is gratuitous.

### Reading the outputs

Each eval writes a CSV (machine-readable) and a `.md` summary (with a built-in
interpretation paragraph). The `delimiter_sensitivity.md` summary automatically
computes the compression-vs-purity trade-off and reports whether attack-aware
delimiters win on this workload.

---

## Disclaimer

This project is provided as-is for educational and security research purposes.
