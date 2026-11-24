# ЛР №4. Інтеграція із NVD API та автоматизоване тестування

Консольна утиліта шукає запис CVE у NVD (CVE API 2.0), вибирає оцінку CVSS v3.1,
застосовує правило свого варіанта та друкує JSON-звіт.

**Варіант 10:** `score >= 6.0` і `privilegesRequired == "LOW"` у тій самій вибраній оцінці.

## Встановлення

З кореня репозиторію, в активованому `.venv` (Python 3.12+):

```bash
pip install requests pytest ruff
pip freeze | grep -i -E "requests|pytest|ruff"   # зафіксувати версії в requirements.txt
```

У `shared/student.py` має бути `VARIANT_NUMBER = VARIANT` (номер варіанта, ціле 1–15).

## Запуск

Локально, без мережі (синтетичний запис `CVE-2099-10001`):

```bash
python -m labs.lab04.main --cve CVE-2099-10001 --input labs/lab04/data/nvd_sample.json
```

Один ручний запит до NVD (за потреби ключ: змінна середовища `NVD_API_KEY`):

```bash
python -m labs.lab04.main --cve CVE-2021-44228
```

Коди завершення: `0` — звіт сформовано (зокрема `not_found`, `insufficient_data`);
`1` — помилка отримання, читання чи перевірки даних; `2` — неправильні аргументи
або номер варіанта. Звіт іде в stdout, повідомлення про помилки — у stderr.

## Формат звіту

Ключі: `cve_id`, `variant`, `description`, `vuln_status`, `cvss_version`, `score`,
`score_source`, `vector`, `rule {threshold, field, expected}`, `observed`, `decision`.
`decision`: `not_found`, `rejected`, `insufficient_data`, `review`, `other`.

## Перевірка

```bash
python -m pytest labs/lab04/tests -q
ruff check labs/lab04
ruff format --check labs/lab04
```

Тести не звертаються до мережі: `tests/conftest.py` забороняє справжні запити Requests
і видаляє `NVD_API_KEY` перед кожним тестом.
