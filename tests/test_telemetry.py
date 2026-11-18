"""Telemetry contract (design §3): always-on tracer, opt-in export, fail-safe."""

from custos.telemetry import install_telemetry


def test_install_without_export_env(monkeypatch) -> None:
    for key in list(__import__("os").environ):
        if key.startswith("OTEL_"):
            monkeypatch.delenv(key, raising=False)
    provider = install_telemetry()
    assert provider is not None
    tracer = provider.get_tracer("custos.test")
    with tracer.start_as_current_span("test-span") as span:
        span.set_attribute("action", "get")
        assert span.is_recording()


def test_bad_otel_config_never_raises(monkeypatch) -> None:
    monkeypatch.setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "not a url at all")
    monkeypatch.setenv("OTEL_METRICS_EXPORTER", "bogus")
    provider = install_telemetry()  # must not raise
    assert provider is not None


def test_request_hook_redacts_query() -> None:
    from opentelemetry.sdk.trace import TracerProvider as SDKProvider

    from custos.telemetry import _redact_request_span

    provider = SDKProvider()
    tracer = provider.get_tracer("t")
    with tracer.start_as_current_span("GET /api/search") as span:
        span.set_attribute("http.url", "http://x/api/search?q=sk-secret-shaped")
        span.set_attribute("http.target", "/api/search?q=sk-secret-shaped")
        span.set_attribute("url.query", "q=sk-secret-shaped")
        _redact_request_span(span, None)
        attrs = dict(span.attributes or {})
        assert "sk-secret-shaped" not in str(attrs)
