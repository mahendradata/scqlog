# scqlog — Score, Cluster, Query
# Converts Apache/NGINX logs to Parquet + interactive HTML dashboards
#
# Build:  docker build -t scqlog .
# Run:    docker run --rm -p 8000:8000 -v "$(pwd)/data:/app/data" scqlog
#         (see README.md for Windows / macOS / Linux variants)

FROM python:3.11-slim

# uv binary from the official image (pinned minor version)
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

WORKDIR /app

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=0 \
    PYTHONUNBUFFERED=1

# Install locked dependencies first (cached unless pyproject.toml / uv.lock change)
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --locked --no-dev --no-install-project

# Install the package itself
COPY scqlog/ ./scqlog/
RUN uv sync --locked --no-dev --no-editable

# Put the project venv on PATH so `scqlog` and `python` resolve to it
ENV PATH="/app/.venv/bin:$PATH"

# Copy evaluation suite and entrypoint
COPY eval/ ./eval/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# data/ is expected to be bind-mounted from the host
RUN mkdir -p data

EXPOSE 8000

# Arguments to `docker run ... scqlog <args>` are passed through to scqlog (e.g. -pl 2)
ENTRYPOINT ["./entrypoint.sh"]
