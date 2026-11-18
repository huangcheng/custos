"""Error envelope and the closed code→status map (design §6).

Messages never contain secret material or submitted values.
"""

from __future__ import annotations

import logging

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

ERROR_STATUS: dict[str, int] = {
    "not_found": 404,
    "read_only": 403,
    "secret_downgrade_denied": 403,
    "setup_complete": 403,
    "session_required": 403,
    "purpose_denied": 403,
    "turnstile_failed": 422,
    "step_up_required": 401,
    "conflict": 409,
    "payload_too_large": 413,
    "rate_limited": 429,
    "history_budget_exceeded": 429,
    "locked_out": 429,
    "invalid": 422,
    "key_unavailable": 500,
    "unauthorized": 401,
    "method_not_allowed": 405,
    "forbidden": 403,
    "internal_error": 500,
}


class AppError(Exception):
    """Application error carrying a closed-set code; status derives from the map."""

    def __init__(self, code: str, message: str = "", headers: dict[str, str] | None = None) -> None:
        if code not in ERROR_STATUS:
            raise ValueError(f"unknown error code {code!r}")
        self.code = code
        self.status = ERROR_STATUS[code]
        self.message = message or code.replace("_", " ")
        self.headers = headers
        super().__init__(self.message)


class _TracebackSanitizer(logging.Filter):
    """Strip exception text/traceback from server error logs (§11: exception
    messages may embed submitted values or secrets). Type + sanitized location
    survive for debuggability; the full traceback never reaches any handler."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.exc_info and record.exc_info[0] is not None:
            exc_type = record.exc_info[0]
            record.exc_info = None
            record.exc_text = None
            record.stack_info = None
            record.args = ()  # lazy %-args may carry submitted values/secrets
            record.msg = f"{record.msg} [exception: {exc_type.__name__}; traceback redacted]"
        return True


_SANITIZER = _TracebackSanitizer()


def install_error_handlers(app: FastAPI) -> None:
    # Logger-level filters miss propagated records; handler-level filters on the
    # root catch everything that reaches an output. Idempotent across app builds.
    root = logging.getLogger()
    if _SANITIZER not in root.filters:
        root.addFilter(_SANITIZER)
    for handler in root.handlers:
        if _SANITIZER not in handler.filters:
            handler.addFilter(_SANITIZER)
    for name in ("uvicorn.error", "uvicorn", "fastapi"):
        logger = logging.getLogger(name)
        if _SANITIZER not in logger.filters:
            logger.addFilter(_SANITIZER)
        for handler in logger.handlers:
            if _SANITIZER not in handler.filters:
                handler.addFilter(_SANITIZER)

    @app.exception_handler(AppError)
    async def _app_error(request: Request, exc: AppError) -> JSONResponse:
        return JSONResponse(
            status_code=exc.status,
            content={"code": exc.code, "message": exc.message},
            headers=exc.headers,
        )

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        code = {
            400: "invalid",
            401: "unauthorized",
            403: "forbidden",
            404: "not_found",
            405: "method_not_allowed",
            409: "conflict",
            413: "payload_too_large",
            422: "invalid",
            429: "rate_limited",
        }.get(exc.status_code)
        if code is None:
            code = "internal_error" if exc.status_code >= 500 else "invalid"
        status = ERROR_STATUS[code]
        return JSONResponse(
            status_code=status,
            content={"code": code, "message": code.replace("_", " ")},
            headers=exc.headers,
        )

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # Never echo submitted input/ctx — validation errors name fields only.
        fields = sorted(
            {
                ".".join(str(part) for part in err.get("loc", ())[1:2])
                for err in exc.errors()
                if len(err.get("loc", ())) > 1
                and err.get("type") not in {"json_invalid", "extra_forbidden"}
            }
            - {""}
        )
        message = "invalid request body" if not fields else "invalid: " + ", ".join(fields)
        return JSONResponse(status_code=422, content={"code": "invalid", "message": message})

    @app.exception_handler(Exception)
    async def _unhandled(request: Request, exc: Exception) -> JSONResponse:
        # Fixed message: exception text may contain submitted values or secrets.
        return JSONResponse(
            status_code=ERROR_STATUS["internal_error"],
            content={"code": "internal_error", "message": "internal error"},
        )
