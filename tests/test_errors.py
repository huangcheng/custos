"""AppError envelope behavior through real HTTP (design §6, §11 no-echo)."""

import httpx
import pytest
from fastapi import FastAPI
from pydantic import BaseModel

from custos.config import load_settings
from custos.errors import AppError
from tests.test_config import env


@pytest.fixture
def app() -> FastAPI:
    from custos.app import create_app

    application = create_app(load_settings(env()))

    class Body(BaseModel):
        value: int

    @application.get("/boom")
    async def boom() -> None:
        raise AppError("conflict", "revision mismatch")

    @application.post("/echo")
    async def echo(body: Body) -> dict[str, int]:
        return {"value": body.value}

    return application


async def test_app_error_envelope(app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/boom")
    assert resp.status_code == 409
    assert resp.json() == {"code": "conflict", "message": "revision mismatch"}


async def test_unknown_route_uses_envelope(app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/does-not-exist")
    assert resp.status_code == 404
    assert resp.json()["code"] == "not_found"


async def test_validation_error_never_echoes_input(app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=app)
    secret_shaped = "sk-very-secret-shaped-value"
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/echo", json={"value": secret_shaped})
    assert resp.status_code == 422
    body = resp.json()
    assert body["code"] == "invalid"
    assert secret_shaped not in resp.text


async def test_405_keeps_status_and_allow_header(app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/healthz")
    assert resp.status_code == 405
    assert resp.json()["code"] == "method_not_allowed"
    assert "GET" in resp.headers.get("allow", "")


async def test_body_level_validation_message(app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/echo", content=b'"just a string"',
                                 headers={"content-type": "application/json"})
    assert resp.status_code == 422
    assert resp.json()["message"] == "invalid request body"


async def test_app_error_carries_retry_after(app: FastAPI) -> None:
    @app.get("/limited")
    async def limited() -> None:
        raise AppError("rate_limited", headers={"Retry-After": "60"})

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/limited")
    assert resp.status_code == 429
    assert resp.headers["retry-after"] == "60"


async def test_framework_403_not_coerced_to_422(app: FastAPI) -> None:
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.get("/forbidden")
    async def forbidden() -> None:
        raise StarletteHTTPException(403)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/forbidden")
    assert resp.status_code == 403
    assert resp.json()["code"] == "forbidden"


async def test_malformed_json_message_no_offset(app: FastAPI) -> None:
    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post(
            "/echo", content=b'{"value": 1,,}', headers={"content-type": "application/json"}
        )
    assert resp.status_code == 422
    assert resp.json()["message"] == "invalid request body"


async def test_framework_409_keeps_conflict(app: FastAPI) -> None:
    from starlette.exceptions import HTTPException as StarletteHTTPException

    @app.get("/clash")
    async def clash() -> None:
        raise StarletteHTTPException(409)

    transport = httpx.ASGITransport(app=app)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/clash")
    assert resp.status_code == 409
    assert resp.json()["code"] == "conflict"


async def test_extra_forbidden_key_never_echoed(app: FastAPI) -> None:
    from pydantic import BaseModel, ConfigDict

    class Strict(BaseModel):
        model_config = ConfigDict(extra="forbid")
        value: int

    @app.post("/strict")
    async def strict(body: Strict) -> dict[str, int]:
        return {"value": body.value}

    transport = httpx.ASGITransport(app=app)
    key = "sk-secret-shaped-key"
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/strict", json={"value": 1, key: 2})
    assert resp.status_code == 422
    assert key not in resp.text


async def test_dict_key_never_echoed(app: FastAPI) -> None:
    from pydantic import BaseModel

    class MapBody(BaseModel):
        data: dict[str, int]

    @app.post("/map")
    async def map_body(body: MapBody) -> dict[str, int]:
        return body.data

    transport = httpx.ASGITransport(app=app)
    key = "sk-secret-shaped-dict-key"
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.post("/map", json={"data": {key: "not-an-int"}})
    assert resp.status_code == 422
    assert key not in resp.text


async def test_unhandled_exception_envelope(app: FastAPI) -> None:
    @app.get("/crash")
    async def crash() -> None:
        raise RuntimeError("sk-secret-in-exception-text")

    transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
    async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
        resp = await client.get("/crash")
    assert resp.status_code == 500
    assert resp.json() == {"code": "internal_error", "message": "internal error"}
    assert "sk-secret" not in resp.text


async def test_unhandled_exception_traceback_sanitized(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    @app.get("/crash2")
    async def crash2() -> None:
        raise RuntimeError("sk-secret-in-exception-text")

    # raise_app_exceptions=True mirrors uvicorn: ServerErrorMiddleware sends the
    # sanitized response, then re-raises; the server logs the exception.
    transport = httpx.ASGITransport(app=app, raise_app_exceptions=True)
    with caplog.at_level(logging.ERROR, logger="uvicorn.error"):
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            try:
                await client.get("/crash2")
            except RuntimeError as exc:
                logging.getLogger("uvicorn.error").error(
                    "Exception in ASGI application", exc_info=exc
                )
    assert "sk-secret-in-exception-text" not in caplog.text


def test_sanitizer_covers_args_and_propagated_records(
    app: FastAPI, caplog: pytest.LogCaptureFixture
) -> None:
    import logging

    from custos.errors import install_error_handlers

    # idempotent installation
    before = len(logging.getLogger("uvicorn.error").filters)
    install_error_handlers(app)
    assert len(logging.getLogger("uvicorn.error").filters) == before

    secret = "sk-lazy-arg-secret"
    try:
        raise RuntimeError("sk-exc-secret")
    except RuntimeError as exc:
        # app-level logger: record propagates to root handlers, bypassing logger filters
        logging.getLogger("custos.some_module").error(
            "failed for %s", secret, exc_info=exc
        )
    assert secret not in caplog.text
    assert "sk-exc-secret" not in caplog.text
