# scqlog — Score, Cluster, Query
# Converts Apache/NGINX logs to Parquet + interactive HTML dashboards

FROM python:3.11-slim

WORKDIR /app

# Install the package and its dependencies in one layer
COPY pyproject.toml README.md ./
COPY scqlog/ ./scqlog/
RUN pip install --no-cache-dir -e .

# Copy evaluation suite and entrypoint
COPY eval/ ./eval/
COPY entrypoint.sh .
RUN chmod +x entrypoint.sh

# data/ is expected to be bind-mounted from the host
RUN mkdir -p data

EXPOSE 8000

CMD ["./entrypoint.sh"]
