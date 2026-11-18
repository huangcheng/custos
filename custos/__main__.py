"""Server entrypoint: ``python -m custos`` (single worker, §3 contract)."""

from __future__ import annotations

import logging

import uvicorn

from custos.app import create_app
from custos.config import load_settings


class _QueryRedactingAccessFilter(logging.Filter):
    """Access lines never carry query strings (§3: search terms can be
    secret-shaped). uvicorn formats the full path into the record args."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.args and len(record.args) >= 3:
            args = list(record.args)
            path = str(args[2])
            if "?" in path:
                args[2] = path.split("?", 1)[0] + "?[redacted]"
            record.args = tuple(args)
        return True


class _TraceFormatter(logging.Formatter):
    """Append trace/span ids (stamped by the telemetry record factory) so
    logs correlate with spans even without an exporter (§3)."""

    def format(self, record: logging.LogRecord) -> str:
        base = super().format(record)
        trace_id = getattr(record, "trace_id", "")
        if trace_id:
            return f"{base} trace_id={trace_id} span_id={getattr(record, 'span_id', '')}"
        return base


def main() -> None:
    handler = logging.StreamHandler()
    handler.setFormatter(_TraceFormatter("%(levelname)s %(name)s: %(message)s"))
    logging.getLogger().addHandler(handler)
    # application logs at INFO; root stays WARNING so third-party INFO
    # (sqlalchemy bind params, httpx request lines) never reaches the log
    # surface (§11). uvicorn's own loggers keep their dictConfig levels.
    logging.getLogger("custos").setLevel(logging.INFO)
    settings = load_settings()
    app = create_app(settings)  # installs the record-factory sanitizer
    logging.getLogger("uvicorn.access").addFilter(_QueryRedactingAccessFilter())
    uvicorn.run(
        app,
        host=settings.bind,
        port=settings.port,
        workers=1,
        access_log=True,
        # The app's trusted-proxy chain (§5) is authoritative: uvicorn must
        # not rewrite scope["client"] from client-supplied X-Forwarded-For.
        proxy_headers=False,
        server_header=False,
    )


if __name__ == "__main__":
    main()
