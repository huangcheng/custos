# ---- console build ----------------------------------------------------------
# Node only exists in this stage: the runtime image stays Python-only.
# The output is architecture-independent, so build it on the native platform
# even when the runtime image is cross-built.
FROM --platform=$BUILDPLATFORM node:22-alpine AS console-build
WORKDIR /build
COPY console/package.json console/package-lock.json ./
RUN npm ci --no-audit --no-fund
COPY console/ ./
# An incomplete dist would make the app serve a JSON 404 for / and look
# "fine" at runtime: fail the BUILD instead.
RUN npm run build && test -f dist/index.html


# ---- cli build -------------------------------------------------------------
# NOT --platform=$BUILDPLATFORM: the binary is native, so it must be built for
# the TARGET platform or a cross-built image ships a binary for the wrong arch.
FROM rust:1-slim-bookworm AS cli-build
WORKDIR /build
COPY cli/Cargo.toml cli/Cargo.lock ./
# a dummy main so the dependency layer caches independently of the sources;
# --locked keeps the dependency set identical to the committed lockfile
RUN mkdir -p src && echo "fn main() {}" > src/main.rs && cargo build --release --locked
# only the sources: copying tests/ would recompile the crate for test-only edits
COPY cli/src ./src
RUN touch src/main.rs && cargo build --release --locked


# ---- runtime ---------------------------------------------------------------
FROM python:3.12-slim-bookworm

WORKDIR /app

# Dependency layer first: source edits do not reinstall the environment.
COPY pyproject.toml uv.lock ./
RUN pip install --no-cache-dir uv==0.11.28 \
    && uv sync --frozen --no-dev --no-install-project --no-cache \
    && (id -u custos >/dev/null 2>&1 || useradd --system --uid 10001 --create-home custos) \
    && { [ "$(id -u custos)" = 10001 ] || { echo "custos uid is $(id -u custos), expected 10001" >&2; exit 1; }; } \
    && install -d -m 0700 -o custos -g custos /var/lib/custos

COPY custos ./custos
COPY alembic.ini ./
COPY alembic ./alembic
RUN uv sync --frozen --no-dev --no-cache

# The operator console (static SPA). Without it the API still works and
# GET / answers a JSON 404.
COPY --from=console-build /build/dist ./console/dist
RUN test -f ./console/dist/index.html

# The operator CLI, for break-glass from the host shell (§9).
COPY --from=cli-build /build/target/release/custos /app/bin/custos
# run it: a glibc mismatch between the two base images would leave a binary
# that exists and is executable but cannot start
RUN /app/bin/custos --version

ENV HOME=/home/custos PYTHONUNBUFFERED=1 PATH="/app/.venv/bin:/app/bin:$PATH" \
    CUSTOS_CONSOLE_DIST=/app/console/dist
USER custos
EXPOSE 8300
ENTRYPOINT []
HEALTHCHECK --interval=10s --timeout=3s --retries=6 --start-period=120s \
    CMD /app/.venv/bin/python -c "import urllib.request;urllib.request.urlopen('http://127.0.0.1:8300/healthz', timeout=2)"
CMD ["/app/.venv/bin/python", "-m", "custos"]
