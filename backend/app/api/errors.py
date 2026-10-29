"""Consistent JSON error envelope: {"error": {"code", "message", "details"}}.

Error responses never echo submitted input or internal exception text.
"""

import logging
from http import HTTPStatus
from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.schemas.errors import ErrorBody, ErrorResponse
from app.services.ioc import IOCValidationError
from app.services.iocs import RelationshipError

logger = logging.getLogger(__name__)

_HTTP_ERROR_CODES = {
    400: "bad_request",
    404: "not_found",
    405: "method_not_allowed",
    409: "conflict",
    411: "length_required",
    413: "payload_too_large",
}


def error_response(
    status_code: int, code: str, message: str, details: dict[str, Any] | None = None
) -> JSONResponse:
    body = ErrorResponse(error=ErrorBody(code=code, message=message, details=details))
    return JSONResponse(status_code=status_code, content=body.model_dump(mode="json"))


async def _ioc_validation_error(_: Request, exc: IOCValidationError) -> JSONResponse:
    details = {"suspected_type": exc.suspected_type.value} if exc.suspected_type else None
    return error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, exc.code, exc.message, details)


async def _relationship_error(_: Request, exc: RelationshipError) -> JSONResponse:
    return error_response(status.HTTP_422_UNPROCESSABLE_CONTENT, "invalid_relationship", str(exc))


async def _request_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    # Pydantic errors include the offending input; drop it so payloads aren't reflected.
    fields = [
        {"loc": ".".join(str(part) for part in err["loc"]), "message": err["msg"]}
        for err in exc.errors()
    ]
    return error_response(
        status.HTTP_422_UNPROCESSABLE_CONTENT,
        "validation_error",
        "Request body is invalid.",
        {"fields": fields},
    )


async def _http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    code = _HTTP_ERROR_CODES.get(exc.status_code, "http_error")
    message = exc.detail if isinstance(exc.detail, str) else HTTPStatus(exc.status_code).phrase
    return error_response(exc.status_code, code, message)


async def _unhandled_error(_: Request, exc: Exception) -> JSONResponse:
    logger.error("Unhandled error: %s", type(exc).__name__)
    return error_response(
        status.HTTP_500_INTERNAL_SERVER_ERROR, "internal_error", "Internal server error."
    )


def register_exception_handlers(app: FastAPI) -> None:
    app.add_exception_handler(IOCValidationError, _ioc_validation_error)
    app.add_exception_handler(RelationshipError, _relationship_error)
    app.add_exception_handler(RequestValidationError, _request_validation_error)
    app.add_exception_handler(StarletteHTTPException, _http_error)
    app.add_exception_handler(Exception, _unhandled_error)
