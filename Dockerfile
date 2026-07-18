FROM python:3.12-slim AS base

WORKDIR /app

COPY src/ src/
COPY tests/ tests/
COPY pyproject.toml .
RUN pip install --no-cache-dir ".[dev]"

RUN python -m pytest tests/ -v

ENTRYPOINT ["seal"]
CMD ["--help"]