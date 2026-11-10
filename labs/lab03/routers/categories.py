"""Маршрути категорій."""

from http import HTTPStatus
from typing import Annotated

from fastapi import APIRouter, Path, Response

from labs.lab03 import repository
from labs.lab03.schemas import CategoryCreate, CategoryRead, ErrorResponse

router = APIRouter(prefix="/categories", tags=["categories"])

CategoryId = Annotated[int, Path(gt=0, description="Ідентифікатор категорії (додатне ціле)")]


@router.get("", response_model=list[CategoryRead], summary="Список категорій")
def list_categories() -> list[dict]:
    """Повернути всі категорії за зростанням id."""
    return repository.list_categories()


@router.post(
    "",
    response_model=CategoryRead,
    status_code=HTTPStatus.CREATED,
    summary="Створити категорію",
    responses={409: {"model": ErrorResponse, "description": "Категорія з такою назвою вже існує"}},
)
def create_category(payload: CategoryCreate) -> dict:
    """Створити нову категорію."""
    return repository.create_category(payload.name)


@router.delete(
    "/{category_id}",
    status_code=HTTPStatus.NO_CONTENT,
    response_class=Response,
    summary="Видалити порожню категорію",
    responses={
        404: {"model": ErrorResponse, "description": "Категорію не знайдено"},
        409: {"model": ErrorResponse, "description": "Категорія містить записи"},
    },
)
def delete_category(category_id: CategoryId) -> Response:
    """Видалити категорію, якщо до неї не прив'язано записів."""
    repository.delete_category(category_id)
    return Response(status_code=HTTPStatus.NO_CONTENT)
