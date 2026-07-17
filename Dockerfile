FROM python:3.12-slim AS base

WORKDIR /app

COPY pyproject.toml .
RUN pip install --no-cache-dir .

COPY src/ src/
COPY tests/ tests/

RUN python -m pytest tests/ -v

ENTRYPOINT ["aegis"]
CMD ["--help"]
