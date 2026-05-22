"""HTML dashboard generator using DuckDB WASM for large-scale log visualization.

Generates self-contained HTML files that query Parquet data in-browser using
DuckDB WASM. Features include:

- DuckDB WHERE clause filtering with real-time validation and example queries
- Clickable column name chips to insert column names into the WHERE input
- Distinct-row toggle to deduplicate results by the currently visible columns
- Column visibility controls (show/hide, resize)
- Sortable columns with ascending/descending toggle
- Paginated results with configurable page size (10, 25, 50, or 100 rows)
- CSV export of filtered/visible data
"""

from pathlib import Path
import html
import json


HTML_TEMPLATE = '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{title}</title>
    <style>
        * {{
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
            margin: 20px;
            background: #f5f5f5;
        }}
        h1 {{
            color: #333;
        }}
        .loading {{
            text-align: center;
            padding: 40px;
            color: #666;
        }}
        .loading .spinner {{
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 40px;
            height: 40px;
            animation: spin 1s linear infinite;
            margin: 0 auto 15px;
        }}
        @keyframes spin {{
            0% {{ transform: rotate(0deg); }}
            100% {{ transform: rotate(360deg); }}
        }}
        .error {{
            background: #f8d7da;
            color: #721c24;
            padding: 15px;
            border-radius: 4px;
            margin-bottom: 15px;
        }}
        .controls {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .stats {{
            color: #666;
        }}
        .control-group {{
            display: flex;
            align-items: center;
            gap: 8px;
        }}
        select, input[type="text"] {{
            padding: 6px 10px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-size: 14px;
        }}
        input[type="text"] {{
            width: 200px;
        }}
        input[type="text"]:focus {{
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
        }}
        .btn {{
            padding: 8px 16px;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
            font-weight: 500;
        }}
        .btn-primary {{
            background: #007bff;
            color: white;
        }}
        .btn-primary:hover {{
            background: #0056b3;
        }}
        .btn-success {{
            background: #28a745;
            color: white;
        }}
        .btn-success:hover {{
            background: #218838;
        }}
        .btn-secondary {{
            background: #6c757d;
            color: white;
        }}
        .btn-secondary:hover {{
            background: #545b62;
        }}
        .btn:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}

        /* Column visibility panel */
        .column-panel {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .column-panel-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .column-panel-header h3 {{
            margin: 0;
            font-size: 14px;
            color: #333;
        }}
        .column-checkboxes {{
            display: flex;
            flex-wrap: wrap;
            gap: 8px;
        }}
        .column-checkbox {{
            display: flex;
            align-items: center;
            gap: 4px;
            padding: 4px 8px;
            background: #f8f9fa;
            border-radius: 4px;
            font-size: 13px;
            cursor: pointer;
        }}
        .column-checkbox:hover {{
            background: #e9ecef;
        }}
        .column-checkbox input {{
            cursor: pointer;
        }}
        .column-checkbox.hidden {{
            opacity: 0.5;
        }}

        .table-container {{
            overflow-x: auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        table {{
            border-collapse: collapse;
            width: max-content;
            min-width: 100%;
            font-size: 14px;
        }}
        th, td {{
            padding: 10px 12px;
            text-align: left;
            border-bottom: 1px solid #e0e0e0;
            white-space: nowrap;
            overflow: hidden;
            text-overflow: ellipsis;
            position: relative;
        }}
        th {{
            background: #f8f9fa;
            font-weight: 600;
            user-select: none;
            position: sticky;
            top: 0;
            min-width: 80px;
        }}
        th .th-content {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            gap: 8px;
        }}
        th .th-text {{
            cursor: pointer;
            flex: 1;
            overflow: hidden;
            text-overflow: ellipsis;
        }}
        th .th-text:hover {{
            color: #007bff;
        }}
        th.sort-asc .th-text::after {{
            content: " ▲";
            font-size: 10px;
        }}
        th.sort-desc .th-text::after {{
            content: " ▼";
            font-size: 10px;
        }}

        /* Resize handle */
        .resize-handle {{
            position: absolute;
            right: 0;
            top: 0;
            bottom: 0;
            width: 6px;
            cursor: col-resize;
            background: transparent;
            z-index: 10;
        }}
        .resize-handle:hover,
        .resize-handle.resizing {{
            background: #007bff;
        }}

        tr:hover {{
            background: #f8f9fa;
        }}
        td {{
            max-width: none;
        }}
        .pagination {{
            display: flex;
            justify-content: center;
            align-items: center;
            gap: 5px;
            margin-top: 15px;
            flex-wrap: wrap;
        }}
        .pagination button {{
            padding: 8px 12px;
            border: 1px solid #ccc;
            background: white;
            border-radius: 4px;
            cursor: pointer;
            font-size: 14px;
        }}
        .pagination button:hover:not(:disabled) {{
            background: #e9ecef;
        }}
        .pagination button:disabled {{
            opacity: 0.5;
            cursor: not-allowed;
        }}
        .pagination button.active {{
            background: #007bff;
            color: white;
            border-color: #007bff;
        }}
        .pagination .page-info {{
            padding: 8px 12px;
            color: #666;
        }}
        .no-results {{
            text-align: center;
            padding: 20px;
            color: #666;
        }}
        #app {{
            display: none;
        }}
        .col-hidden {{
            display: none !important;
        }}

        /* WHERE clause panel */
        .where-panel {{
            background: white;
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .where-panel-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .where-panel-header h3 {{
            margin: 0;
            font-size: 14px;
            color: #333;
        }}
        .where-input-container {{
            display: flex;
            gap: 10px;
            margin-bottom: 10px;
        }}
        .where-prefix {{
            background: #e9ecef;
            padding: 8px 12px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            color: #495057;
            white-space: nowrap;
            align-self: flex-start;
        }}
        #where-input {{
            flex: 1;
            min-height: 60px;
            padding: 8px 12px;
            border: 1px solid #ccc;
            border-radius: 4px;
            font-family: monospace;
            font-size: 13px;
            resize: vertical;
        }}
        #where-input:focus {{
            outline: none;
            border-color: #007bff;
            box-shadow: 0 0 0 2px rgba(0,123,255,0.25);
        }}
        #where-input.input-error {{
            border-color: #dc3545;
            box-shadow: 0 0 0 2px rgba(220,53,69,0.25);
        }}
        .where-error {{
            background: #f8d7da;
            color: #721c24;
            padding: 10px 12px;
            border-radius: 4px;
            margin-top: 10px;
            font-size: 13px;
            display: none;
        }}
        .where-error.visible {{
            display: block;
        }}

        /* Example queries */
        .example-queries {{
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #eee;
        }}
        .example-queries-header {{
            font-size: 12px;
            color: #666;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        .example-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        .example-query {{
            background: #f0f7ff;
            border: 1px solid #b3d7ff;
            color: #0056b3;
            padding: 4px 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .example-query:hover {{
            background: #007bff;
            border-color: #007bff;
            color: white;
        }}
        .where-actions {{
            display: flex;
            gap: 8px;
            align-items: center;
        }}

        /* Clickable column names for query building */
        .column-names {{
            margin-top: 12px;
            padding-top: 12px;
            border-top: 1px solid #eee;
        }}
        .column-names-header {{
            font-size: 12px;
            color: #666;
            margin-bottom: 8px;
            font-weight: 500;
        }}
        .column-names-list {{
            display: flex;
            flex-wrap: wrap;
            gap: 6px;
        }}
        .column-name-btn {{
            background: #f5f0ff;
            border: 1px solid #d4c4f0;
            color: #6b4c9a;
            padding: 4px 10px;
            border-radius: 4px;
            font-family: monospace;
            font-size: 12px;
            cursor: pointer;
            transition: all 0.15s ease;
        }}
        .column-name-btn:hover {{
            background: #6b4c9a;
            border-color: #6b4c9a;
            color: white;
        }}
    </style>
</head>
<body>
    <h1>{title}</h1>

    <div id="loading" class="loading">
        <div class="spinner"></div>
        <div>Loading DuckDB and data...</div>
    </div>

    <div id="error" class="error" style="display: none;"></div>

    <div id="app">
        <!-- WHERE clause filter panel -->
        <div class="where-panel">
            <div class="where-panel-header">
                <h3>DuckDB WHERE Filter</h3>
                <div class="where-actions">
                    <button class="btn btn-secondary" id="clear-where-btn" style="padding: 4px 8px; font-size: 12px;">Clear</button>
                    <button class="btn btn-primary" id="apply-where-btn" style="padding: 4px 8px; font-size: 12px;">Apply Filter</button>
                </div>
            </div>
            <div class="where-input-container">
                <span class="where-prefix">WHERE</span>
                <textarea id="where-input" placeholder="Enter a valid DuckDB WHERE clause, e.g.: status >= 400 AND method = 'GET'"></textarea>
            </div>
            <div style="font-size: 11px; color: #888; margin-bottom: 8px;">Press <kbd style="background:#eee;padding:1px 4px;border-radius:3px;border:1px solid #ccc;">Ctrl+Enter</kbd> to apply, or click Apply Filter. Query is validated as you type.</div>
            <label style="display: inline-flex; align-items: center; gap: 6px; font-size: 12px; margin-bottom: 8px; cursor: pointer; user-select: none;">
                <input type="checkbox" id="distinct-checkbox">
                <span>Distinct rows (dedupe by visible columns)</span>
            </label>
            <div class="where-error" id="where-error"></div>
            <div class="example-queries">
                <div class="example-queries-header">Example Queries (click to use):</div>
                <div class="example-list" id="example-list"></div>
            </div>
            <div class="column-names">
                <div class="column-names-header">Available Columns (click to insert):</div>
                <div class="column-names-list" id="column-names-list"></div>
            </div>
        </div>

        <!-- Column visibility panel -->
        <div class="column-panel">
            <div class="column-panel-header">
                <h3>Visible Columns</h3>
                <div>
                    <button class="btn btn-secondary" id="show-all-btn" style="padding: 4px 8px; font-size: 12px;">Show All</button>
                    <button class="btn btn-secondary" id="hide-all-btn" style="padding: 4px 8px; font-size: 12px;">Hide All</button>
                </div>
            </div>
            <div class="column-checkboxes" id="column-checkboxes"></div>
        </div>

        <div class="controls">
            <span class="stats" id="stats">Total entries: -</span>
            <div class="control-group">
                <label for="page-size">Rows per page:</label>
                <select id="page-size">
                    <option value="10">10</option>
                    <option value="25" selected>25</option>
                    <option value="50">50</option>
                    <option value="100">100</option>
                </select>
            </div>
            <button class="btn btn-success" id="export-btn">Export to CSV</button>
        </div>

        <div class="table-container">
            <table id="log-table">
                <thead><tr id="table-header"></tr></thead>
                <tbody id="table-body"></tbody>
            </table>
        </div>

        <div class="pagination" id="pagination"></div>
    </div>

    <script type="module">
        // DuckDB WASM CDN
        import * as duckdb from 'https://cdn.jsdelivr.net/npm/@duckdb/duckdb-wasm@1.28.0/+esm';

        const PARQUET_FILE = '{parquet_filename}';
        const COLUMNS = {columns_json};

        // Example WHERE queries for user guidance
        const EXAMPLE_QUERIES = [
            {{ query: "status >= 400", description: "Error responses (4xx, 5xx)" }},
            {{ query: "url LIKE '%admin%'", description: "Admin URLs" }},
            {{ query: "host = '192.168.1.1'", description: "Specific IP" }},
            {{ query: "sqli_score > 0 OR xss_score > 0", description: "SQL injection or XSS detected" }},
            {{ query: "method = 'POST'", description: "POST requests only" }},
            {{ query: "CAST(size AS INTEGER) > 10000", description: "Large responses (>10KB)" }},
            {{ query: "webshell_score > 0", description: "Webshell probing" }},
            {{ query: "status = 404", description: "Not found errors" }},
            {{ query: "path_traversal_score > 3 OR lfi_score > 3", description: "Path traversal/LFI attacks" }},
        ];

        let db = null;
        let conn = null;
        let totalRows = 0;
        let currentPage = 1;
        let pageSize = 25;
        let sortColumn = null;
        let sortAsc = true;
        let whereClause = '';
        let whereDebounceTimer = null;
        let distinctMode = false;

        // Column visibility state
        let visibleColumns = new Set(COLUMNS);
        let columnWidths = {{}};

        // DOM elements
        const loadingDiv = document.getElementById('loading');
        const errorDiv = document.getElementById('error');
        const appDiv = document.getElementById('app');
        const statsSpan = document.getElementById('stats');
        const pageSizeSelect = document.getElementById('page-size');
        const exportBtn = document.getElementById('export-btn');
        const tableHeader = document.getElementById('table-header');
        const tableBody = document.getElementById('table-body');
        const paginationDiv = document.getElementById('pagination');
        const columnCheckboxes = document.getElementById('column-checkboxes');
        const showAllBtn = document.getElementById('show-all-btn');
        const hideAllBtn = document.getElementById('hide-all-btn');
        const whereInput = document.getElementById('where-input');
        const whereError = document.getElementById('where-error');
        const exampleList = document.getElementById('example-list');
        const columnNamesList = document.getElementById('column-names-list');
        const clearWhereBtn = document.getElementById('clear-where-btn');
        const applyWhereBtn = document.getElementById('apply-where-btn');
        const distinctCheckbox = document.getElementById('distinct-checkbox');

        // Resize state
        let isResizing = false;
        let resizeColumn = null;
        let resizeStartX = 0;
        let resizeStartWidth = 0;

        function showError(message) {{
            errorDiv.textContent = message;
            errorDiv.style.display = 'block';
            loadingDiv.style.display = 'none';
        }}

        function escapeHtml(text) {{
            const div = document.createElement('div');
            div.textContent = text;
            return div.innerHTML;
        }}

        function insertAtCursor(textarea, text) {{
            // Insert text at cursor position without overwriting existing content
            const start = textarea.selectionStart;
            const end = textarea.selectionEnd;
            const before = textarea.value.substring(0, start);
            const after = textarea.value.substring(end);

            textarea.value = before + text + after;

            // Move cursor to end of inserted text
            const newPos = start + text.length;
            textarea.selectionStart = newPos;
            textarea.selectionEnd = newPos;

            // Focus the textarea and trigger input event for validation
            textarea.focus();
            textarea.dispatchEvent(new Event('input'));
        }}

        async function initDuckDB() {{
            try {{
                const JSDELIVR_BUNDLES = duckdb.getJsDelivrBundles();
                const bundle = await duckdb.selectBundle(JSDELIVR_BUNDLES);

                const worker_url = URL.createObjectURL(
                    new Blob([`importScripts("${{bundle.mainWorker}}");`], {{ type: 'text/javascript' }})
                );

                const worker = new Worker(worker_url);
                const logger = new duckdb.ConsoleLogger();
                db = new duckdb.AsyncDuckDB(logger, worker);
                await db.instantiate(bundle.mainModule, bundle.pthreadWorker);
                URL.revokeObjectURL(worker_url);

                conn = await db.connect();

                const response = await fetch(PARQUET_FILE);
                if (!response.ok) {{
                    throw new Error(`Failed to load ${{PARQUET_FILE}}: ${{response.status}}`);
                }}
                const parquetData = await response.arrayBuffer();
                await db.registerFileBuffer(PARQUET_FILE, new Uint8Array(parquetData));

                const countResult = await conn.query(`SELECT COUNT(*) as cnt FROM '${{PARQUET_FILE}}'`);
                totalRows = Number(countResult.getChildAt(0).get(0));

                initializeUI();

                loadingDiv.style.display = 'none';
                appDiv.style.display = 'block';

                await loadData();
            }} catch (error) {{
                showError(`Error initializing: ${{error.message}}`);
                console.error(error);
            }}
        }}

        function initializeUI() {{
            // Build column visibility checkboxes
            COLUMNS.forEach(col => {{
                const label = document.createElement('label');
                label.className = 'column-checkbox';
                label.dataset.column = col;

                const checkbox = document.createElement('input');
                checkbox.type = 'checkbox';
                checkbox.checked = true;
                checkbox.addEventListener('change', () => {{
                    toggleColumn(col, checkbox.checked);
                    if (distinctMode) {{
                        currentPage = 1;
                        loadData();
                    }}
                }});

                const span = document.createElement('span');
                span.textContent = col;

                label.appendChild(checkbox);
                label.appendChild(span);
                columnCheckboxes.appendChild(label);
            }});

            // Build table header with resize handles
            COLUMNS.forEach(col => {{
                const th = document.createElement('th');
                th.dataset.column = col;

                const content = document.createElement('div');
                content.className = 'th-content';

                const text = document.createElement('span');
                text.className = 'th-text';
                text.textContent = col;
                text.addEventListener('click', () => handleSort(col));

                const handle = document.createElement('div');
                handle.className = 'resize-handle';
                handle.addEventListener('mousedown', (e) => startResize(e, th, col));

                content.appendChild(text);
                th.appendChild(content);
                th.appendChild(handle);
                tableHeader.appendChild(th);
            }});

            // Show/Hide all buttons
            showAllBtn.addEventListener('click', () => {{
                COLUMNS.forEach(col => toggleColumn(col, true));
                columnCheckboxes.querySelectorAll('input').forEach(cb => cb.checked = true);
                if (distinctMode) {{
                    currentPage = 1;
                    loadData();
                }}
            }});

            hideAllBtn.addEventListener('click', () => {{
                COLUMNS.forEach(col => toggleColumn(col, false));
                columnCheckboxes.querySelectorAll('input').forEach(cb => cb.checked = false);
                if (distinctMode) {{
                    currentPage = 1;
                    loadData();
                }}
            }});

            // Resize event listeners
            document.addEventListener('mousemove', handleResize);
            document.addEventListener('mouseup', stopResize);

            // Build example queries
            EXAMPLE_QUERIES.forEach(example => {{
                const btn = document.createElement('button');
                btn.className = 'example-query';
                btn.textContent = example.query;
                btn.title = example.description;
                btn.addEventListener('click', () => {{
                    whereInput.value = example.query;
                    applyWhereFilter();
                }});
                exampleList.appendChild(btn);
            }});

            // Build clickable column names for query building
            COLUMNS.forEach(col => {{
                const btn = document.createElement('button');
                btn.className = 'column-name-btn';
                btn.textContent = col;
                btn.title = `Insert "${{col}}" into query`;
                btn.addEventListener('click', () => {{
                    insertAtCursor(whereInput, col);
                }});
                columnNamesList.appendChild(btn);
            }});

            // WHERE clause event listeners
            clearWhereBtn.addEventListener('click', clearWhereFilter);
            applyWhereBtn.addEventListener('click', applyWhereFilter);
            distinctCheckbox.addEventListener('change', () => {{
                distinctMode = distinctCheckbox.checked;
                currentPage = 1;
                loadData();
            }});
            whereInput.addEventListener('input', handleWhereInputChange);
            whereInput.addEventListener('keydown', (e) => {{
                if (e.key === 'Enter' && e.ctrlKey) {{
                    e.preventDefault();
                    applyWhereFilter();
                }}
            }});
        }}

        function toggleColumn(col, visible) {{
            if (visible) {{
                visibleColumns.add(col);
            }} else {{
                visibleColumns.delete(col);
            }}

            const colIndex = COLUMNS.indexOf(col);

            // Update header
            const th = tableHeader.children[colIndex];
            th.classList.toggle('col-hidden', !visible);

            // Update checkbox style
            const checkbox = columnCheckboxes.querySelector(`[data-column="${{col}}"]`);
            if (checkbox) {{
                checkbox.classList.toggle('hidden', !visible);
            }}

            // Update body cells
            tableBody.querySelectorAll('tr').forEach(tr => {{
                if (tr.children[colIndex]) {{
                    tr.children[colIndex].classList.toggle('col-hidden', !visible);
                }}
            }});
        }}

        function startResize(e, th, col) {{
            e.preventDefault();
            e.stopPropagation();
            isResizing = true;
            resizeColumn = col;
            resizeStartX = e.pageX;
            resizeStartWidth = th.offsetWidth;
            th.querySelector('.resize-handle').classList.add('resizing');
            document.body.style.cursor = 'col-resize';
            document.body.style.userSelect = 'none';
        }}

        function handleResize(e) {{
            if (!isResizing) return;

            const colIndex = COLUMNS.indexOf(resizeColumn);
            const th = tableHeader.children[colIndex];
            const newWidth = Math.max(80, resizeStartWidth + (e.pageX - resizeStartX));

            th.style.width = newWidth + 'px';
            th.style.minWidth = newWidth + 'px';
            th.style.maxWidth = newWidth + 'px';
            columnWidths[resizeColumn] = newWidth;

            // Apply to body cells
            tableBody.querySelectorAll('tr').forEach(tr => {{
                if (tr.children[colIndex]) {{
                    tr.children[colIndex].style.width = newWidth + 'px';
                    tr.children[colIndex].style.minWidth = newWidth + 'px';
                    tr.children[colIndex].style.maxWidth = newWidth + 'px';
                }}
            }});
        }}

        function stopResize() {{
            if (isResizing) {{
                const colIndex = COLUMNS.indexOf(resizeColumn);
                const th = tableHeader.children[colIndex];
                th.querySelector('.resize-handle').classList.remove('resizing');
                isResizing = false;
                resizeColumn = null;
                document.body.style.cursor = '';
                document.body.style.userSelect = '';
            }}
        }}

        function getActiveColumns() {{
            // When distinct mode is on, query returns only visible columns (in COLUMNS order).
            // Otherwise, query returns all columns.
            if (distinctMode) {{
                const vis = COLUMNS.filter(c => visibleColumns.has(c));
                return vis.length > 0 ? vis : COLUMNS;
            }}
            return COLUMNS;
        }}

        function buildQuery(forCount = false, forExport = false) {{
            const useDistinct = distinctMode && visibleColumns.size > 0;
            const activeCols = getActiveColumns();
            const selectList = useDistinct
                ? activeCols.map(c => `"${{c}}"`).join(', ')
                : '*';

            const whereSql = (whereClause && whereClause.trim())
                ? ` WHERE ${{whereClause.trim()}}`
                : '';

            if (forCount) {{
                if (useDistinct) {{
                    return `SELECT COUNT(*) as cnt FROM (SELECT DISTINCT ${{selectList}} FROM '${{PARQUET_FILE}}'${{whereSql}}) sub`;
                }}
                return `SELECT COUNT(*) as cnt FROM '${{PARQUET_FILE}}'${{whereSql}}`;
            }}

            const distinctKw = useDistinct ? 'DISTINCT ' : '';
            let query = `SELECT ${{distinctKw}}${{selectList}} FROM '${{PARQUET_FILE}}'${{whereSql}}`;

            // Only sort when sortColumn is in the active result columns
            if (sortColumn && activeCols.includes(sortColumn)) {{
                query += ` ORDER BY "${{sortColumn}}" ${{sortAsc ? 'ASC' : 'DESC'}}`;
            }}

            if (!forExport) {{
                const offset = (currentPage - 1) * pageSize;
                query += ` LIMIT ${{pageSize}} OFFSET ${{offset}}`;
            }}

            return query;
        }}

        function showWhereError(message) {{
            whereError.textContent = message;
            whereError.classList.add('visible');
            whereInput.classList.add('input-error');
        }}

        function clearWhereError() {{
            whereError.textContent = '';
            whereError.classList.remove('visible');
            whereInput.classList.remove('input-error');
        }}

        async function validateWhereClause(clause) {{
            if (!clause || !clause.trim()) {{
                return {{ valid: true }};
            }}

            // Basic syntax checks before executing
            const trimmed = clause.trim().toUpperCase();

            // Check for forbidden clauses that could modify data or structure
            const forbidden = ['DROP', 'DELETE', 'INSERT', 'UPDATE', 'ALTER', 'CREATE', 'TRUNCATE', 'EXEC', 'EXECUTE'];
            for (const word of forbidden) {{
                const regex = new RegExp(`\\\\b${{word}}\\\\b`, 'i');
                if (regex.test(clause)) {{
                    return {{ valid: false, error: `Forbidden keyword "${{word}}" detected. Only SELECT queries are allowed.` }};
                }}
            }}

            // Try to execute a validation query with LIMIT 0
            try {{
                const testQuery = `SELECT 1 FROM '${{PARQUET_FILE}}' WHERE ${{clause}} LIMIT 0`;
                await conn.query(testQuery);
                return {{ valid: true }};
            }} catch (error) {{
                // Parse DuckDB error message for user-friendly display
                let errorMsg = error.message || 'Invalid WHERE clause';

                // Clean up common error patterns
                if (errorMsg.includes('Binder Error')) {{
                    const match = errorMsg.match(/Binder Error: (.+)/);
                    errorMsg = match ? match[1] : errorMsg;
                }} else if (errorMsg.includes('Parser Error')) {{
                    const match = errorMsg.match(/Parser Error: (.+)/);
                    errorMsg = match ? match[1] : errorMsg;
                }}

                return {{ valid: false, error: errorMsg }};
            }}
        }}

        async function applyWhereFilter() {{
            const newClause = whereInput.value.trim();
            clearWhereError();

            // Validate the WHERE clause
            const validation = await validateWhereClause(newClause);
            if (!validation.valid) {{
                showWhereError(validation.error);
                return;
            }}

            whereClause = newClause;
            currentPage = 1;
            await loadData();
        }}

        function clearWhereFilter() {{
            whereInput.value = '';
            whereClause = '';
            clearWhereError();
            currentPage = 1;
            loadData();
        }}

        function handleWhereInputChange() {{
            // Clear any previous error when user starts typing
            clearWhereError();

            // Debounce auto-apply (500ms delay)
            if (whereDebounceTimer) {{
                clearTimeout(whereDebounceTimer);
            }}
            whereDebounceTimer = setTimeout(async () => {{
                const newClause = whereInput.value.trim();

                // Only auto-validate, don't auto-apply (user must click Apply or press Ctrl+Enter)
                if (newClause) {{
                    const validation = await validateWhereClause(newClause);
                    if (!validation.valid) {{
                        showWhereError(validation.error);
                    }}
                }}
            }}, 500);
        }}

        async function loadData() {{
            try {{
                const countQuery = buildQuery(true);
                const countResult = await conn.query(countQuery);
                const filteredCount = Number(countResult.getChildAt(0).get(0));

                // Update stats display
                if (whereClause) {{
                    statsSpan.textContent = `Showing ${{filteredCount.toLocaleString()}} of ${{totalRows.toLocaleString()}} entries (filtered)`;
                }} else {{
                    statsSpan.textContent = `Total entries: ${{totalRows.toLocaleString()}}`;
                }}

                const dataQuery = buildQuery();
                const result = await conn.query(dataQuery);

                renderTable(result, filteredCount);

                // Clear any previous global errors on successful load
                errorDiv.style.display = 'none';
            }} catch (error) {{
                // If there's a WHERE clause, show the error in the WHERE panel
                if (whereClause) {{
                    showWhereError(`Query error: ${{error.message}}`);
                }} else {{
                    showError(`Query error: ${{error.message}}`);
                }}
                console.error(error);
            }}
        }}

        function renderTable(result, filteredCount) {{
            tableBody.innerHTML = '';

            const numRows = result.numRows;

            if (numRows === 0) {{
                const tr = document.createElement('tr');
                const td = document.createElement('td');
                td.colSpan = COLUMNS.length;
                td.className = 'no-results';
                td.textContent = 'No matching records found';
                tr.appendChild(td);
                tableBody.appendChild(tr);
                paginationDiv.innerHTML = '';
                return;
            }}

            const activeCols = getActiveColumns();
            for (let i = 0; i < numRows; i++) {{
                const tr = document.createElement('tr');
                COLUMNS.forEach((col, colIndex) => {{
                    const td = document.createElement('td');
                    const resultIdx = activeCols.indexOf(col);
                    if (resultIdx >= 0) {{
                        const value = result.getChildAt(resultIdx).get(i);
                        td.textContent = value !== null ? String(value) : '';
                    }} else {{
                        td.textContent = '';
                    }}
                    td.title = td.textContent;

                    // Apply saved width
                    if (columnWidths[col]) {{
                        td.style.width = columnWidths[col] + 'px';
                        td.style.minWidth = columnWidths[col] + 'px';
                        td.style.maxWidth = columnWidths[col] + 'px';
                    }}

                    // Apply visibility
                    if (!visibleColumns.has(col)) {{
                        td.classList.add('col-hidden');
                    }}

                    tr.appendChild(td);
                }});
                tableBody.appendChild(tr);
            }}

            // Update header sort indicators
            document.querySelectorAll('#table-header th').forEach(th => {{
                th.classList.remove('sort-asc', 'sort-desc');
                if (th.dataset.column === sortColumn) {{
                    th.classList.add(sortAsc ? 'sort-asc' : 'sort-desc');
                }}
            }});

            renderPagination(filteredCount);
        }}

        function renderPagination(filteredCount) {{
            paginationDiv.innerHTML = '';

            const totalPages = Math.ceil(filteredCount / pageSize) || 1;

            if (totalPages <= 1) return;

            const prevBtn = document.createElement('button');
            prevBtn.textContent = '← Previous';
            prevBtn.disabled = currentPage === 1;
            prevBtn.addEventListener('click', () => {{
                if (currentPage > 1) {{
                    currentPage--;
                    loadData();
                }}
            }});
            paginationDiv.appendChild(prevBtn);

            const maxVisible = 5;
            let startPage = Math.max(1, currentPage - Math.floor(maxVisible / 2));
            let endPage = Math.min(totalPages, startPage + maxVisible - 1);

            if (endPage - startPage < maxVisible - 1) {{
                startPage = Math.max(1, endPage - maxVisible + 1);
            }}

            if (startPage > 1) {{
                addPageButton(1);
                if (startPage > 2) {{
                    const ellipsis = document.createElement('span');
                    ellipsis.textContent = '...';
                    ellipsis.className = 'page-info';
                    paginationDiv.appendChild(ellipsis);
                }}
            }}

            for (let i = startPage; i <= endPage; i++) {{
                addPageButton(i);
            }}

            if (endPage < totalPages) {{
                if (endPage < totalPages - 1) {{
                    const ellipsis = document.createElement('span');
                    ellipsis.textContent = '...';
                    ellipsis.className = 'page-info';
                    paginationDiv.appendChild(ellipsis);
                }}
                addPageButton(totalPages);
            }}

            const nextBtn = document.createElement('button');
            nextBtn.textContent = 'Next →';
            nextBtn.disabled = currentPage === totalPages;
            nextBtn.addEventListener('click', () => {{
                if (currentPage < totalPages) {{
                    currentPage++;
                    loadData();
                }}
            }});
            paginationDiv.appendChild(nextBtn);

            const pageInfo = document.createElement('span');
            pageInfo.className = 'page-info';
            const start = (currentPage - 1) * pageSize + 1;
            const end = Math.min(currentPage * pageSize, filteredCount);
            pageInfo.textContent = `(${{start}}-${{end}} of ${{filteredCount}})`;
            paginationDiv.appendChild(pageInfo);
        }}

        function addPageButton(pageNum) {{
            const btn = document.createElement('button');
            btn.textContent = pageNum;
            if (pageNum === currentPage) {{
                btn.classList.add('active');
            }}
            btn.addEventListener('click', () => {{
                currentPage = pageNum;
                loadData();
            }});
            paginationDiv.appendChild(btn);
        }}

        function handleSort(column) {{
            if (sortColumn === column) {{
                sortAsc = !sortAsc;
            }} else {{
                sortColumn = column;
                sortAsc = true;
            }}
            currentPage = 1;
            loadData();
        }}

        async function exportToCsv() {{
            try {{
                exportBtn.disabled = true;
                exportBtn.textContent = 'Exporting...';

                const exportQuery = buildQuery(false, true);
                const result = await conn.query(exportQuery);

                const csvRows = [];

                // Only export visible columns
                const exportCols = COLUMNS.filter(col => visibleColumns.has(col));
                const activeCols = getActiveColumns();
                csvRows.push(exportCols.map(col => escapeCsvValue(col)).join(','));

                const numRows = result.numRows;
                for (let i = 0; i < numRows; i++) {{
                    const rowData = exportCols.map(col => {{
                        const resultIdx = activeCols.indexOf(col);
                        if (resultIdx < 0) return escapeCsvValue('');
                        const value = result.getChildAt(resultIdx).get(i);
                        return escapeCsvValue(value !== null ? String(value) : '');
                    }});
                    csvRows.push(rowData.join(','));
                }}

                const csvContent = csvRows.join('\\n');

                const blob = new Blob([csvContent], {{ type: 'text/csv;charset=utf-8;' }});
                const url = URL.createObjectURL(blob);
                const link = document.createElement('a');
                link.href = url;
                link.download = 'filtered_export.csv';
                document.body.appendChild(link);
                link.click();
                document.body.removeChild(link);
                URL.revokeObjectURL(url);
            }} catch (error) {{
                showError(`Export error: ${{error.message}}`);
            }} finally {{
                exportBtn.disabled = false;
                exportBtn.textContent = 'Export to CSV';
            }}
        }}

        function escapeCsvValue(value) {{
            const str = String(value);
            if (str.includes('"') || str.includes(',') || str.includes('\\n') || str.includes('\\r')) {{
                return '"' + str.replace(/"/g, '""') + '"';
            }}
            return str;
        }}

        // Event listeners
        pageSizeSelect.addEventListener('change', () => {{
            pageSize = parseInt(pageSizeSelect.value);
            currentPage = 1;
            loadData();
        }});
        exportBtn.addEventListener('click', exportToCsv);

        // Initialize
        initDuckDB();
    </script>
</body>
</html>'''


def generate_html(parquet_filename: str, title: str, output_path: Path, columns: list[str]) -> None:
    """
    Generate an HTML dashboard that uses DuckDB WASM to query Parquet files.

    The generated dashboard includes:
    - DuckDB WHERE clause input with real-time validation
    - Clickable example queries for common filters
    - Column visibility toggles and resizable columns
    - Sortable table headers
    - Paginated results (10, 25, 50, or 100 rows per page)
    - CSV export functionality

    Args:
        parquet_filename: Name of the Parquet file (relative to HTML location)
        title: Title displayed in the HTML page header
        output_path: Path where the HTML file will be written
        columns: List of column names to display in the table
    """
    html_content = HTML_TEMPLATE.format(
        title=html.escape(title),
        parquet_filename=parquet_filename,
        columns_json=json.dumps(columns)
    )

    output_path.write_text(html_content, encoding='utf-8')
