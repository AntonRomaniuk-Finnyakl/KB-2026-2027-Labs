"""FastAPI-застосунок: облік навантаження серверних ресурсів (варіант 10)."""

import logging
import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException, Request
from fastapi.exception_handlers import http_exception_handler
from fastapi.responses import JSONResponse

from labs.lab03 import repository
from labs.lab03.config import APP_DESCRIPTION, APP_TITLE
from labs.lab03.database import initialize_database
from labs.lab03.routers import categories, records
from labs.lab03.schemas import StatusRead, StudentRead
from shared.student import GROUP, STUDENT_NAME, VARIANT

logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
logger = logging.getLogger("lab03.api")


@asynccontextmanager
async def lifespan(_app: FastAPI) -> AsyncIterator[None]:
    """Створити відсутні таблиці під час запуску (дані не змінюються)."""
    initialize_database()
    yield


app = FastAPI(title=APP_TITLE, description=APP_DESCRIPTION, version="1.0.0", lifespan=lifespan)
app.include_router(categories.router)
app.include_router(records.router)


@app.exception_handler(repository.NotFoundError)
async def not_found_handler(request: Request, exc: repository.NotFoundError):
    """404: запис або категорію не знайдено."""
    return await http_exception_handler(request, HTTPException(status_code=404, detail=str(exc)))


@app.exception_handler(repository.ConflictError)
async def conflict_handler(request: Request, exc: repository.ConflictError):
    """409: дублікат або порушення зв'язку."""
    return await http_exception_handler(request, HTTPException(status_code=409, detail=str(exc)))


@app.exception_handler(sqlite3.Error)
async def sqlite_error_handler(_request: Request, exc: sqlite3.Error) -> JSONResponse:
    """500: технічні подробиці лише в журнал, клієнту — загальне повідомлення."""
    logger.error("Помилка бази даних: %s", exc, exc_info=exc)
    return JSONResponse(status_code=500, content={"detail": "Внутрішня помилка сервера"})


@app.get("/ping", response_model=StatusRead, tags=["service"], summary="Перевірка доступності API")
def ping() -> dict[str, str]:
    """Повернути {"status": "ok"}."""
    return {"status": "ok"}


@app.get("/student", response_model=StudentRead, tags=["service"], summary="Дані студента")
def student() -> dict[str, object]:
    """Повернути ПІБ, групу та номер варіанта з shared/student.py."""
    return {"student_name": STUDENT_NAME, "group_name": GROUP, "variant_number": VARIANT}
