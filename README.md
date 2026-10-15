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

You need **one** of the following, depending on how you want to run scqlog:

| Option | What you need | Best for |
|--------|---------------|----------|
| **A. Native Python with `uv`** | [uv](https://docs.astral.sh/uv/) (it downloads Python 3.11+ for you if needed) and [Git](https://git-scm.com/downloads) | Development, running the eval suite, processing logs anywhere on disk |
| **B. Docker** | [Docker Desktop](https://www.docker.com/products/docker-desktop/) (Windows/macOS) or Docker Engine 20.10+ (Linux) and Git | One command, no Python setup on the host |

Both options need a **modern browser** with WebAssembly support (Chrome, Firefox,
Safari, Edge) to view the dashboard.

Python dependencies are declared in `pyproject.toml` and locked in `uv.lock`:
`pandas`, `pyarrow`, and `drain3` (log template clustering), plus their transitive
dependencies.

---

## Installation

### 1. Get the source code (all platforms)

```bash
git clone https://github.com/mahendradata/scqlog
cd scqlog
```

### 2A. Native install with `uv`

**Install uv** (once per machine):

| OS | Command |
|----|---------|
| **Windows** (PowerShell) | `powershell -ExecutionPolicy ByPass -c "irm https://astral.sh/uv/install.ps1 \| iex"` <br>or `winget install --id=astral-sh.uv -e` |
| **macOS** | `curl -LsSf https://astral.sh/uv/install.sh \| sh` <br>or `brew install uv` |
| **Linux** | `curl -LsSf https://astral.sh/uv/install.sh \| sh` |

Close and reopen your terminal afterwards so `uv` is on your `PATH`, then check
it with `uv --version`.

**Install scqlog and its dependencies** (from the `scqlog` directory; the
command is the same on Windows, macOS and Linux):

```bash
uv sync
```

This creates a project virtual environment in `.venv/` with the exact versions
from `uv.lock`. If no suitable interpreter is found, uv installs Python 3.11 first
(the version is pinned in `.python-version`). You don't need to activate the
environment: prefix commands with `uv run`.

### 2B. Docker install

1. Install Docker:
   - **Windows**: [Docker Desktop for Windows](https://docs.docker.com/desktop/setup/install/windows-install/)
     (WSL 2 backend recommended). Start Docker Desktop before using `docker`.
   - **macOS**: [Docker Desktop for Mac](https://docs.docker.com/desktop/setup/install/mac-install/)
     (pick the Apple Silicon or Intel build). Start Docker Desktop before using `docker`.
   - **Linux**: [Docker Engine](https://docs.docker.com/engine/install/) for your
     distribution. To run `docker` without `sudo`, add yourself to the `docker` group
     (`sudo usermod -aG docker $USER`), then log out and back in.
2. Build the image (from the `scqlog` directory; same on every platform):

   ```bash
   docker build -t scqlog .
   ```

   Rebuild after pulling new code. The image installs from the same `uv.lock`, so it
   has exactly the same dependency versions as the native install.

---

## Usage

For each input `path/to/access.log`, scqlog writes its outputs to a sibling
directory named after the file stem: `path/to/access/access.parquet` and
`path/to/access/access.html`.

The dashboard loads the Parquet file over HTTP, so it **must be opened through a
web server**, not by double-clicking the HTML file (`file://` URLs block the fetch).
Both options below include that step.

The examples use the bundled `data/samples.log`. Put your own `.log` files in
`data/` (or anywhere else, for Option A).

### Option A: Native Python with `uv`

These commands work the same in Windows PowerShell, the macOS Terminal and Linux shells:

```bash
# 1. Process one or more log files
uv run scqlog data/samples.log

# 2. Serve the data/ directory
uv run python -m http.server 8000 --directory data

# 3. Open http://localhost:8000/samples/samples.html in your browser.
#    Press Ctrl+C in the terminal to stop the server.
```

More examples:

```bash
# Several files at once (macOS / Linux shells expand the wildcard)
uv run scqlog data/*.log
# Windows PowerShell does not expand wildcards for programs; list the files
uv run scqlog data/a.log data/b.log

# Raise the OWASP CRS paranoia level (1 = fewest false positives, 4 = max detection)
uv run scqlog -pl 2 data/samples.log
uv run scqlog --paranoia-level 4 data/samples.log

# Logs outside the repository work too; outputs go next to the input file
uv run scqlog /var/log/nginx/access.log        # macOS / Linux
uv run scqlog C:\logs\access.log               # Windows

# Show version / help
uv run scqlog --version
uv run scqlog --help
```

> **Tip:** if you prefer an activated environment, run `.venv\Scripts\activate`
> (Windows PowerShell) or `source .venv/bin/activate` (macOS/Linux) once. After that
> you can type `scqlog ...` and `python -m http.server ...` without the `uv run` prefix.

**CLI flags:**

| Flag | Default | Description |
|------|---------|-------------|
| `-pl`, `--paranoia-level {1,2,3,4}` | `CRS_PARANOIA_LEVEL` env var, else `1` | OWASP CRS paranoia level — higher detects more attacks but increases false-positive rate |
| `--version` | — | Print version and exit |

### Option B: Docker

The container processes **every `*.log` file** in the mounted directory, then
serves that directory on port 8000. Mount your log directory at `/app/data`:

**Windows (PowerShell):**

```powershell
docker run --rm -p 8000:8000 -v "${PWD}\data:/app/data" scqlog
```

**Windows (Command Prompt):**

```bat
docker run --rm -p 8000:8000 -v "%cd%\data:/app/data" scqlog
```

**macOS:**

```bash
docker run --rm -p 8000:8000 -v "$(pwd)/data:/app/data" scqlog
```

**Linux** (the `--user` flag makes the generated files owned by you instead of root):

```bash
docker run --rm -p 8000:8000 --user "$(id -u):$(id -g)" -v "$(pwd)/data:/app/data" scqlog
```

Then open <http://localhost:8000/samples/samples.html> (in general,
`http://localhost:8000/<basename>/<basename>.html`). Press `Ctrl+C` to stop the
container. Because `data/` is bind-mounted, the generated files stay in your
local `data/` directory, and you can serve them again later with Option A or any static
web server.

More examples (shown with the macOS/Linux mount syntax; on Windows, use the
mount syntax shown above):

```bash
# Arguments after the image name are passed to scqlog, e.g. paranoia level 2
docker run --rm -p 8000:8000 -v "$(pwd)/data:/app/data" scqlog -pl 2

# Or set it through the environment
docker run --rm -p 8000:8000 -e CRS_PARANOIA_LEVEL=3 -v "$(pwd)/data:/app/data" scqlog

# Port 8000 already in use? Map another host port, then open http://localhost:8080/...
docker run --rm -p 8080:8000 -v "$(pwd)/data:/app/data" scqlog

# Run the evaluation suite inside the container (no web server)
docker run --rm -v "$(pwd)/data:/app/data" --entrypoint python scqlog \
  -m eval.run_all data/samples.log      # reports land in data/samples_eval/
```

> **Note:** the container writes its output folders into the mounted directory. If you
> mount a system log directory such as `/var/log/nginx` directly, copy the logs into
> `data/` first unless you want the output folders created there.

### Troubleshooting

| Symptom | Fix |
|---------|-----|
| Dashboard is blank or shows a fetch error | You opened the HTML via `file://`. Serve it over HTTP as shown above. |
| `uv: command not found` / `uv is not recognized` | Reopen the terminal after installing uv, or add `~/.local/bin` (macOS/Linux) or `%USERPROFILE%\.local\bin` (Windows) to `PATH`. |
| Docker: `no .log files found in /app/data` | The `-v` path is wrong or the directory has no `*.log` files. Use an absolute path or the `$(pwd)` / `${PWD}` / `%cd%` forms above. |
| Docker: `port is already allocated` | Use a different host port, e.g. `-p 8080:8000`. |
| Docker on Windows: `exec ./entrypoint.sh: no such file or directory` | `entrypoint.sh` was checked out with CRLF line endings. Delete `entrypoint.sh`, run `git checkout -- entrypoint.sh` to re-create it with LF endings, then rebuild. `.gitattributes` keeps it LF for fresh clones. |
| Linux: permission errors when deleting outputs | The container created the files as root. Use `--user "$(id -u):$(id -g)"` as shown, or `sudo rm -r data/<basename>`. |

---

## Project Structure

```
scqlog/                          # Root of the repository
├── pyproject.toml               # Package metadata + `scqlog` console-script entry point
├── uv.lock                      # Locked dependency versions (used by `uv sync` and Docker)
├── .python-version              # Python version uv uses for the native install (3.11)
├── Dockerfile                   # Container image (uv-based install)
├── entrypoint.sh                # Docker entrypoint (runs scqlog on data/*.log, then serves data/)
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
dataset is required. With `eval.run_all`, CSV + markdown reports are written next to
the input log in `<basename>_eval/` (e.g. `data/access_eval/`); change this with
`--output-dir`.

### Running an eval

```bash
# All three at once (writes a README.md index in the output dir)
uv run python -m eval.run_all data/access.log

# Or one at a time
uv run python -m eval.paranoia_sensitivity   data/access.log
uv run python -m eval.cluster_stability      data/access.log --n-runs 10
uv run python -m eval.delimiter_sensitivity  data/access.log -pl 2

# Cap the number of lines parsed for quick iteration
uv run python -m eval.run_all data/access.log --max-lines 50000
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
