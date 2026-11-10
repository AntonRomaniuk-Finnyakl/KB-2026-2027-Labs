"""Початкове заповнення бази з data/seed.json."""

import json
import logging
import sqlite3
import sys
from pathlib import Path
from typing import Any

from labs.lab03 import repository
from labs.lab03.config import STATUSES, VALUE_MAX, VALUE_MIN
from labs.lab03.database import initialize_database

logger = logging.getLogger("lab03.seed")

SEED_PATH = Path(__file__).resolve().parent / "data" / "seed.json"
CATEGORY_KEYS = {"id", "name"}
RECORD_KEYS = {"code", "title", "category_id", "value", "status"}


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _is_number(value: object) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def validate_seed(data: Any) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Перевірити структуру seed-даних; ValueError, якщо дані некоректні."""
    if not isinstance(data, dict) or set(data) != {"categories", "records"}:
        raise ValueError("JSON має бути об'єктом з ключами categories і records")
    categories, records = data["categories"], data["records"]
    if not isinstance(categories, list) or not isinstance(records, list):
        raise ValueError("categories і records мають бути масивами")
    for item in categories:
        if not isinstance(item, dict) or set(item) != CATEGORY_KEYS:
            raise ValueError(f"Некоректна категорія: {item!r}")
        if not _is_int(item["id"]) or item["id"] <= 0 or not isinstance(item["name"], str):
            raise ValueError(f"Некоректна категорія: {item!r}")
    known_ids = {item["id"] for item in categories}
    for item in records:
        if not isinstance(item, dict) or set(item) != RECORD_KEYS:
            raise ValueError(f"Некоректний запис: {item!r}")
        if not (isinstance(item["code"], str) and isinstance(item["title"], str)):
            raise ValueError(f"Некоректний запис: {item!r}")
        if not _is_int(item["category_id"]) or item["category_id"] not in known_ids:
            raise ValueError(f"Невідома категорія у записі {item['code']}")
        if not _is_number(item["value"]) or not VALUE_MIN <= item["value"] <= VALUE_MAX:
            raise ValueError(f"Значення поза діапазоном у записі {item['code']}")
        if item["status"] not in STATUSES:
            raise ValueError(f"Недозволений статус у записі {item['code']}")
    return categories, records


def load_seed(path: Path = SEED_PATH) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Прочитати та перевірити JSON."""
    return validate_seed(json.loads(path.read_text(encoding="utf-8")))


def run_seed(path: Path = SEED_PATH) -> int:
    """Заповнити порожню базу; повертає код завершення процесу."""
    initialize_database()
    try:
        categories, records = load_seed(path)
    except (OSError, ValueError) as exc:
        logger.error("Початкові дані некоректні: %s", exc)
        return 1
    if not repository.is_database_empty():
        logger.info("База вже містить дані: заповнення пропущено, дублікатів немає.")
        return 0
    try:
        repository.insert_seed_data(categories, records)
    except sqlite3.Error as exc:
        logger.error("Заповнення скасовано, усі зміни відкотено: %s", exc)
        return 1
    logger.info("Додано категорій: %d, записів: %d.", len(categories), len(records))
    return 0


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    sys.exit(run_seed())
