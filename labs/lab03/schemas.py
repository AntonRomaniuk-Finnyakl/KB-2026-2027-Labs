"""Pydantic-моделі запитів і відповідей."""

from pydantic import BaseModel, ConfigDict, Field

from labs.lab03.config import VALUE_MAX, VALUE_MIN, Status


class CategoryCreate(BaseModel):
    """Тіло запиту створення категорії."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    name: str = Field(min_length=2, max_length=40, description="Назва категорії (cpu, memory, disk ...)")


class CategoryRead(CategoryCreate):
    """Категорія у відповіді."""

    id: int


class RecordCreate(BaseModel):
    """Тіло запиту створення запису (id задає база)."""

    model_config = ConfigDict(str_strip_whitespace=True, extra="forbid")

    code: str = Field(min_length=3, max_length=40, description="Унікальний код, наприклад V10-01")
    title: str = Field(min_length=3, max_length=120, description="Назва вимірювання")
    category_id: int = Field(gt=0, description="Ідентифікатор категорії")
    value: float = Field(
        ge=VALUE_MIN,
        le=VALUE_MAX,
        allow_inf_nan=False,
        description="Використання ресурсу, % (0–100)",
    )
    status: Status = Field(description="Стан перевірки: new, in_progress, done")


class RecordReplace(RecordCreate):
    """Тіло PUT: усі змінювані поля обов'язкові."""


class RecordRead(RecordCreate):
    """Запис у відповіді: змінювані поля, id та назва категорії."""

    id: int
    category_name: str


class StudentRead(BaseModel):
    """Дані студента з shared/student.py."""

    student_name: str
    group_name: str
    variant_number: int


class StatusRead(BaseModel):
    """Відповідь перевірки доступності."""

    status: str


class ErrorResponse(BaseModel):
    """Формат повідомлення про помилку."""

    detail: str
