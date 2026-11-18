"""Entrypoint hardening: query redaction in access logs (§3)."""

import logging

from custos.__main__ import _QueryRedactingAccessFilter


def test_access_query_redacted(caplog) -> None:
    logger = logging.getLogger("uvicorn.access")
    logger.addFilter(_QueryRedactingAccessFilter())
    try:
        with caplog.at_level(logging.INFO, logger="uvicorn.access"):
            logger.info(
                '%s - "%s %s HTTP/%s" %d',
                "127.0.0.1:1",
                "GET",
                "/api/search?q=sk-secret-shaped",
                "1.1",
                200,
            )
        assert "sk-secret-shaped" not in caplog.text
        assert "?[redacted]" in caplog.text
    finally:
        logger.filters = [
            f for f in logger.filters if not isinstance(f, _QueryRedactingAccessFilter)
        ]
