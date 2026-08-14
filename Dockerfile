FROM python:3.12-slim AS builder

ENV PIP_DISABLE_PIP_VERSION_CHECK=1
WORKDIR /build
COPY pyproject.toml README.md ./
COPY src ./src
RUN pip wheel --no-cache-dir --wheel-dir /wheels .

FROM python:3.12-slim

RUN apt-get update \
    && apt-get install --no-install-recommends -y nmap \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 app
COPY --from=builder /wheels /wheels
RUN pip install --no-cache-dir /wheels/* && rm -rf /wheels

USER 10001:10001
EXPOSE 8000
CMD ["uvicorn", "nmapaas.api:app", "--host", "0.0.0.0", "--port", "8000"]
