# ЛР №3 — FastAPI + SQLite

**Варіант 10:** Облік навантаження серверних ресурсів.

## Предметна область

Сервіс зберігає навчальні вимірювання використання серверних ресурсів.

| Поле | Опис |
|---|---|
| категорія (`categories.name`) | ресурс: `cpu`, `memory`, `disk` |
| `code` | унікальний код запису, наприклад `V10-01` |
| `title` | назва вимірювання, наприклад `Вимірювання сервера 01` |
| `value` | використання ресурсу, **відсотки (percent)**, число 0–100 |
| `status` | стан перевірки: `new`, `in_progress`, `done` |

Поріг навантаження: **80.0 %** (приклад: `GET /records?min_value=80`).
Усі дані навчальні.

## Структура

```
labs/lab03/
├── main.py          # FastAPI-застосунок, lifespan, обробники помилок, /ping, /student
├── database.py      # з'єднання SQLite (foreign_keys = ON) та виконання schema.sql
├── schema.sql       # готова схема (таблиці categories і records)
├── repository.py    # усі параметризовані SQL-запити та транзакції
├── schemas.py       # Pydantic-моделі
├── config.py        # одиниця, поріг, діапазон значень, статуси
├── seed.py          # початкове заповнення з data/seed.json
├── routers/
│   ├── categories.py
│   └── records.py
└── data/
    ├── seed.json    # навчальні дані (у Git)
    └── lab3.sqlite3 # створюється програмою (НЕ у Git)
```

## Встановлення (з кореня репозиторію)

```bash
pip install -r requirements.txt
```

## Запуск

```bash
python -m labs.lab03.seed
uvicorn labs.lab03.main:app --reload --host 127.0.0.1 --port 8000
```

- Swagger UI: http://127.0.0.1:8000/docs
- OpenAPI-схема: http://127.0.0.1:8000/openapi.json

`seed` створює базу (якщо її немає) й додає 3 категорії та 8 записів в одній транзакції.
Повторний запуск нічого не змінює і повідомляє, що база вже заповнена.
Якщо дані некоректні — усі зміни відкочуються.

## Маршрути

| Метод і шлях | Призначення | Успіх |
|---|---|---|
| `GET /ping` | перевірка доступності | 200 |
| `GET /student` | дані студента | 200 |
| `GET /categories` | список категорій | 200 |
| `POST /categories` | створити категорію | 201 |
| `DELETE /categories/{category_id}` | видалити порожню категорію | 204 |
| `GET /records` | список із фільтрами | 200 |
| `GET /records/{record_id}` | один запис | 200 |
| `POST /records` | створити запис | 201 |
| `PUT /records/{record_id}` | повна заміна змінюваних полів | 200 |
| `DELETE /records/{record_id}` | видалити запис | 204 |
| `POST /records/bulk` | атомарне пакетне створення (1–100) | 201 |

Параметри `GET /records`: `category_id`, `status`, `min_value`, `q`, `limit` (1–100, типово 20), `offset`.
Фільтри поєднуються через AND, сортування за `id`.

Помилки: `404` — запис/категорію не знайдено; `409` — дублікат `code` чи назви категорії або видалення непорожньої категорії;
`422` — некоректні дані; `500` — загальна помилка сервера (подробиці лише в журналі).

## Приклади запитів

```bash
curl -i "http://127.0.0.1:8000/ping"
curl -i "http://127.0.0.1:8000/records?category_id=1&status=new&limit=5&offset=0"
curl -i "http://127.0.0.1:8000/records?min_value=80"

curl -i -X POST "http://127.0.0.1:8000/records" \
  -H "Content-Type: application/json" \
  -d '{"code":"V10-TEST","title":"Навчальне вимірювання","category_id":1,"value":75.5,"status":"new"}'

# скасування пакета: V10-01 вже існує => 409, V10-ROLLBACK не зберігається
curl -i -X POST "http://127.0.0.1:8000/records/bulk" \
  -H "Content-Type: application/json" \
  -d '[{"code":"V10-ROLLBACK","title":"Перший елемент","category_id":1,"value":40.0,"status":"new"},{"code":"V10-01","title":"Дублікат коду","category_id":2,"value":50.0,"status":"new"}]'
```

У Windows PowerShell зручніше виконувати запити через Swagger UI (`/docs`).

## Перевірка стилю

```bash
ruff check labs/lab03
ruff format --check labs/lab03
ruff check .
ruff format --check .
```
