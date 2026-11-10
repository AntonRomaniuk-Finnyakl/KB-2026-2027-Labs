"""Маршрути записів."""

from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Body, Path, Query, Response

from labs.lab03 import repository
from labs.lab03.config import VALUE_MAX, VALUE_MIN, Status
from labs.lab03.schemas import ErrorResponse, RecordCreate, RecordRead, RecordReplace

router = APIRouter(prefix="/records", tags=["records"])

RecordId = Annotated[int, Path(gt=0, description="Ідентифікатор запису (додатне ціле)")]

NOT_FOUND = {404: {"model": ErrorResponse, "description": "Запис або категорію не знайдено"}}
CONFLICT = {409: {"model": ErrorResponse, "description": "Запис з таким code вже існує"}}


@router.get("", response_model=list[RecordRead], summary="Список записів з фільтрами")
def list_records(
    category_id: Annotated[int | None, Query(gt=0, description="Лише записи цієї категорії")] = None,
    status: Annotated[Status | None, Query(description="Лише записи з цим статусом")] = None,
    min_value: Annotated[
        float | None,
        Query(ge=VALUE_MIN, le=VALUE_MAX, allow_inf_nan=False, description="value >= min_value"),
    ] = None,
    q: Annotated[
        str | None,
        Query(min_length=1, max_length=120, description="Буквальний підрядок у title (з урахуванням регістру)"),
    ] = None,
    limit: Annotated[int, Query(ge=1, le=100, description="Максимальна кількість записів")] = 20,
    offset: Annotated[int, Query(ge=0, description="Скільки записів пропустити")] = 0,
) -> list[dict]:
    """Повернути записи (фільтри поєднуються через AND), відсортовані за id."""
    return repository.list_records(category_id, status, min_value, q, limit, offset)


@router.post(
    "/bulk",
    response_model=list[RecordRead],
    status_code=HTTPStatus.CREATED,
    summary="Пакетне створення записів (атомарно)",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_records_bulk(
    items: Annotated[list[RecordCreate], Body(min_length=1, max_length=100)],
) -> list[dict]:
    """Додати від 1 до 100 записів в одній транзакції: або всі, або жодного."""
    return repository.create_records_bulk([item.model_dump() for item in items])


@router.post(
    "",
    response_model=RecordRead,
    status_code=HTTPStatus.CREATED,
    summary="Створити запис",
    responses={**NOT_FOUND, **CONFLICT},
)
def create_record(payload: RecordCreate) -> dict:
    """Створити запис; id задає база."""
    return repository.create_record(payload.model_dump())


@router.get("/{record_id}", response_model=RecordRead, summary="Отримати запис", responses=NOT_FOUND)
def get_record(record_id: RecordId) -> dict:
    """Повернути один запис разом з category_name."""
    return repository.get_record(record_id)


@router.put(
    "/{record_id}",
    response_model=RecordRead,
    summary="Повністю замінити змінювані поля запису",
    responses={**NOT_FOUND, **CONFLICT},
)
def replace_record(record_id: RecordId, payload: RecordReplace) -> dict:
    """Замінити всі змінювані поля запису; id не змінюється."""
    return repository.replace_record(record_id, payload.model_dump())


@router.delete(
    "/{record_id}",
    status_code=HTTPStatus.NO_CONTENT,
    response_class=Response,
    summary="Видалити запис",
    responses=NOT_FOUND,
)
def delete_record(record_id: RecordId) -> Response:
    """Видалити запис за id."""
    repository.delete_record(record_id)
    return Response(status_code=HTTPStatus.NO_CONTENT)
