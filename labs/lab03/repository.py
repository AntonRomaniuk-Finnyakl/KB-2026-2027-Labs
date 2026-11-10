"""Параметризовані SQL-запити. Модуль не залежить від FastAPI."""

import sqlite3
from contextlib import closing
from typing import Any

from labs.lab03.database import get_connection

FETCH_RECORD_SQL = """
SELECT r.id, r.code, r.title, r.category_id,
       c.name AS category_name, r.value, r.status
FROM records AS r
JOIN categories AS c ON c.id = r.category_id
WHERE r.id = ?
"""

LIST_RECORDS_SQL = """
SELECT r.id, r.code, r.title, r.category_id,
       c.name AS category_name, r.value, r.status
FROM records AS r
JOIN categories AS c ON c.id = r.category_id
WHERE (? IS NULL OR r.category_id = ?)
  AND (? IS NULL OR r.status = ?)
  AND (? IS NULL OR r.value >= ?)
  AND (? IS NULL OR instr(r.title, ?) > 0)
ORDER BY r.id ASC
LIMIT ? OFFSET ?
"""


class RepositoryError(Exception):
    """Базова помилка шару доступу до даних."""


class NotFoundError(RepositoryError):
    """Запис або категорія не існує."""


class ConflictError(RepositoryError):
    """Дублікат унікального значення або порушення зв'язку."""


def _open() -> sqlite3.Connection:
    """Відкрити з'єднання, що повертає рядки як словникоподібні об'єкти."""
    connection = get_connection()
    connection.row_factory = sqlite3.Row
    return connection


def _translate(exc: sqlite3.IntegrityError) -> Exception:
    """Перетворити помилку цілісності SQLite на помилку предметної області."""
    message = str(exc)
    if "categories.name" in message:
        return ConflictError("Категорія з такою назвою вже існує")
    if "records.code" in message:
        return ConflictError("Запис з таким code вже існує")
    if "FOREIGN KEY" in message:
        return ConflictError("Порушено зв'язок між категорією та записами")
    return exc


def _category_exists(connection: sqlite3.Connection, category_id: int) -> bool:
    row = connection.execute("SELECT 1 FROM categories WHERE id = ?", (category_id,)).fetchone()
    return row is not None


def _fetch_record(connection: sqlite3.Connection, record_id: int) -> dict[str, Any] | None:
    row = connection.execute(FETCH_RECORD_SQL, (record_id,)).fetchone()
    return dict(row) if row is not None else None


def _require_record(connection: sqlite3.Connection, record_id: int) -> dict[str, Any]:
    record = _fetch_record(connection, record_id)
    if record is None:
        raise NotFoundError("Запис не знайдено")
    return record


def _ensure_category(connection: sqlite3.Connection, category_id: int) -> None:
    if not _category_exists(connection, category_id):
        raise NotFoundError("Категорію не знайдено")


def _insert_record(connection: sqlite3.Connection, data: dict[str, Any]) -> int:
    """Додати один запис без commit; повертає його id."""
    _ensure_category(connection, data["category_id"])
    cursor = connection.execute(
        "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
        (data["code"], data["title"], data["category_id"], data["value"], data["status"]),
    )
    return int(cursor.lastrowid)


def _delete_empty_category(connection: sqlite3.Connection, category_id: int) -> None:
    _ensure_category(connection, category_id)
    used = connection.execute("SELECT COUNT(*) FROM records WHERE category_id = ?", (category_id,)).fetchone()[0]
    if used > 0:
        raise ConflictError("Категорія містить записи, її не можна видалити")
    connection.execute("DELETE FROM categories WHERE id = ?", (category_id,))


def _update_record(connection: sqlite3.Connection, record_id: int, data: dict[str, Any]) -> dict[str, Any]:
    _require_record(connection, record_id)
    _ensure_category(connection, data["category_id"])
    connection.execute(
        "UPDATE records SET code = ?, title = ?, category_id = ?, value = ?, status = ? WHERE id = ?",
        (data["code"], data["title"], data["category_id"], data["value"], data["status"], record_id),
    )
    return _require_record(connection, record_id)


def _insert_many(connection: sqlite3.Connection, items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Додати весь пакет в одній транзакції (без commit на кожен елемент)."""
    for category_id in sorted({item["category_id"] for item in items}):
        _ensure_category(connection, category_id)
    new_ids = [_insert_record(connection, item) for item in items]
    return [_require_record(connection, record_id) for record_id in new_ids]


# --- Категорії -------------------------------------------------------------


def create_category(name: str) -> dict[str, Any]:
    """Створити категорію."""
    with closing(_open()) as connection:
        try:
            with connection:
                cursor = connection.execute("INSERT INTO categories (name) VALUES (?)", (name,))
                return {"id": cursor.lastrowid, "name": name}
        except sqlite3.IntegrityError as exc:
            raise _translate(exc) from exc


def list_categories() -> list[dict[str, Any]]:
    """Список категорій за зростанням id."""
    with closing(_open()) as connection:
        rows = connection.execute("SELECT id, name FROM categories ORDER BY id").fetchall()
    return [dict(row) for row in rows]


def delete_category(category_id: int) -> None:
    """Видалити порожню категорію."""
    with closing(_open()) as connection:
        try:
            with connection:
                _delete_empty_category(connection, category_id)
        except sqlite3.IntegrityError as exc:
            raise _translate(exc) from exc


# --- Записи ----------------------------------------------------------------


def create_record(data: dict[str, Any]) -> dict[str, Any]:
    """Створити запис."""
    with closing(_open()) as connection:
        try:
            with connection:
                record_id = _insert_record(connection, data)
                return _require_record(connection, record_id)
        except sqlite3.IntegrityError as exc:
            raise _translate(exc) from exc


def get_record(record_id: int) -> dict[str, Any]:
    """Отримати запис за id (разом з category_name)."""
    with closing(_open()) as connection:
        return _require_record(connection, record_id)


def list_records(
    category_id: int | None = None,
    status: str | None = None,
    min_value: float | None = None,
    q: str | None = None,
    limit: int = 20,
    offset: int = 0,
) -> list[dict[str, Any]]:
    """Список записів з необов'язковими фільтрами (AND), сортування за id."""
    params = (
        category_id,
        category_id,
        status,
        status,
        min_value,
        min_value,
        q,
        q,
        limit,
        offset,
    )
    with closing(_open()) as connection:
        rows = connection.execute(LIST_RECORDS_SQL, params).fetchall()
    return [dict(row) for row in rows]


def replace_record(record_id: int, data: dict[str, Any]) -> dict[str, Any]:
    """Повністю замінити змінювані поля запису (id незмінний)."""
    with closing(_open()) as connection:
        try:
            with connection:
                return _update_record(connection, record_id, data)
        except sqlite3.IntegrityError as exc:
            raise _translate(exc) from exc


def delete_record(record_id: int) -> None:
    """Видалити запис; якщо id немає — NotFoundError."""
    with closing(_open()) as connection, connection:
        cursor = connection.execute("DELETE FROM records WHERE id = ?", (record_id,))
        if cursor.rowcount == 0:
            raise NotFoundError("Запис не знайдено")


def create_records_bulk(items: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Атомарно додати пакет записів: або всі, або жодного."""
    with closing(_open()) as connection:
        try:
            with connection:
                return _insert_many(connection, items)
        except sqlite3.IntegrityError as exc:
            raise _translate(exc) from exc


# --- Початкове заповнення --------------------------------------------------


def is_database_empty() -> bool:
    """Чи порожні обидві таблиці."""
    with closing(_open()) as connection:
        categories = connection.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
        records = connection.execute("SELECT COUNT(*) FROM records").fetchone()[0]
    return categories == 0 and records == 0


def insert_seed_data(categories: list[dict[str, Any]], records: list[dict[str, Any]]) -> None:
    """Додати категорії (з заданими id) та записи в одній транзакції."""
    with closing(_open()) as connection, connection:
        connection.executemany(
            "INSERT INTO categories (id, name) VALUES (?, ?)",
            [(item["id"], item["name"]) for item in categories],
        )
        connection.executemany(
            "INSERT INTO records (code, title, category_id, value, status) VALUES (?, ?, ?, ?, ?)",
            [(r["code"], r["title"], r["category_id"], r["value"], r["status"]) for r in records],
        )
