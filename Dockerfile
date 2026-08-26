# The linux/amd64 manifest digest is pinned; the tag is retained for readability.
FROM python:3.10.16-slim-bookworm@sha256:5fb1a18941b20a1be253974bf5ad9e63c9e251279856649b356178962e8908a2

ARG UV_VERSION=0.11.32

ENV DEBIAN_FRONTEND=noninteractive \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    UV_LINK_MODE=copy \
    PATH="/workspace/.venv/bin:${PATH}"

RUN apt-get update \
    && apt-get install --yes --no-install-recommends bash ca-certificates curl git \
    && rm -rf /var/lib/apt/lists/* \
    && python -m pip install --no-cache-dir "uv==${UV_VERSION}"

WORKDIR /workspace
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project
COPY src ./src
COPY configs ./configs
RUN uv sync --frozen --no-dev

ENTRYPOINT ["python", "-m", "src.common.preflight"]
CMD ["--profile", "phase1", "--output", "/tmp/maxvera-environment.json"]
