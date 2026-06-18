FROM mcr.microsoft.com/playwright/python:v1.60.0-jammy

RUN apt-get update && apt-get install -y --no-install-recommends \
    tini \
    libpango-1.0-0 \
    libpangoft2-1.0-0 \
    libcairo2 \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

COPY --from=ghcr.io/astral-sh/uv:0.11.15 /uv /uvx /bin/

ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    PYTHONUNBUFFERED=1

RUN useradd --create-home --shell /bin/bash aegis_user
USER aegis_user
WORKDIR /home/aegis_user/app

# Wymuszenie ścieżki modułów (Bulletproof import)
ENV PYTHONPATH="/home/aegis_user/app/src"

COPY --chown=aegis_user:aegis_user pyproject.toml uv.lock ./
RUN uv sync --frozen --no-install-project --no-dev

COPY --chown=aegis_user:aegis_user src/ ./src/
COPY --chown=aegis_user:aegis_user payloads/ ./payloads/

RUN uv sync --frozen --no-dev --no-editable
RUN mkdir -p /home/aegis_user/app/reports && \
    chmod 700 /home/aegis_user/app/reports

# Bezpośrednie wywołanie Pythona z .venv przez tini (zapobiega procesom Zombie)
ENTRYPOINT ["/usr/bin/tini", "--", "/home/aegis_user/app/.venv/bin/python", "-m", "aegis.cli"]
CMD ["--help"]