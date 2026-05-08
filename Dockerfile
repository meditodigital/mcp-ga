FROM python:3.13-slim

WORKDIR /app

COPY pyproject.toml README.md ./
COPY analytics_mcp ./analytics_mcp
COPY generate_secrets.py ./

RUN pip install --no-cache-dir .

CMD ["analytics-mcp"]
