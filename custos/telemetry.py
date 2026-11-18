"""OpenTelemetry (design §3): TracerProvider always installed (trace ids in
logs even without an exporter); OTLP HTTP export opt-in via the standard
OTEL_* env; bad config never blocks startup. Spans carry actor/action/
item-name attributes only — never field values or tokens.
"""

from __future__ import annotations

import logging
import os

from opentelemetry import trace
from opentelemetry.sdk.resources import Resource
from opentelemetry.sdk.trace import TracerProvider

logger = logging.getLogger("custos.telemetry")


_PROVIDER: TracerProvider | None = None
_FACTORY_INSTALLED = False


def install_telemetry() -> TracerProvider:
    global _PROVIDER
    if _PROVIDER is not None:  # set_tracer_provider is one-shot per process
        return _PROVIDER
    provider = TracerProvider(resource=Resource.create({"service.name": "custos"}))
    endpoint = (
        os.environ.get("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
    )
    if endpoint:
        try:
            from opentelemetry.exporter.otlp.proto.http.trace_exporter import OTLPSpanExporter
            from opentelemetry.sdk.trace.export import BatchSpanProcessor

            provider.add_span_processor(BatchSpanProcessor(OTLPSpanExporter()))
        except Exception:
            # bad OTEL_* config never blocks startup (§3)
            logger.warning("OTLP export configuration invalid; continuing without export")
    trace.set_tracer_provider(provider)
    # LogRecordFactory covers ALL loggers incl. propagated child records
    # (ancestor filters do not run for them).
    global _FACTORY_INSTALLED
    if not _FACTORY_INSTALLED:
        old_factory = logging.getLogRecordFactory()

        def _factory(*args: object, **kwargs: object) -> logging.LogRecord:
            record = old_factory(*args, **kwargs)
            span = trace.get_current_span()
            ctx = span.get_span_context()
            record.trace_id = format(ctx.trace_id, "032x") if ctx.trace_id else ""
            record.span_id = format(ctx.span_id, "016x") if ctx.span_id else ""
            return record

        logging.setLogRecordFactory(_factory)
        _FACTORY_INSTALLED = True
    _PROVIDER = provider
    import atexit

    atexit.register(shutdown_telemetry)
    return provider


def shutdown_telemetry() -> None:
    if _PROVIDER is not None:
        _PROVIDER.shutdown()


def _redact_request_span(span: object, scope: object) -> None:
    """Query strings can be secret-shaped (§3/§11): never export them.
    Per-attribute guards: one bad attribute never disables the rest."""
    attrs = dict(getattr(span, "attributes", None) or {})
    for key, value in attrs.items():
        try:
            if key == "url.query" and value:
                span.set_attribute(key, "[redacted]")  # type: ignore[attr-defined]
            elif isinstance(value, str) and "?" in value:
                span.set_attribute(key, value.split("?", 1)[0])  # type: ignore[attr-defined]
        except Exception:
            logger.warning("span attribute %s could not be redacted", key)


def instrument_fastapi(app: object) -> None:
    from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor

    FastAPIInstrumentor.instrument_app(
        app,  # type: ignore[arg-type]
        server_request_hook=_redact_request_span,
    )


def instrument_engine(engine: object) -> None:
    try:
        from opentelemetry.instrumentation.sqlalchemy import SQLAlchemyInstrumentor

        SQLAlchemyInstrumentor().instrument(engine=engine)
    except Exception:
        logger.warning("SQLAlchemy instrumentation unavailable")
