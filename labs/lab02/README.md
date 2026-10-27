# ЛР №2 — Розробка консольних утиліт для задач кібербезпеки

**Варіант 10:** Монітор термінів дії SSL/TLS сертифікатів  
(`shared/student.py` → `VARIANT = 10`; вхідні дані — `data/data_v10/certificates.json`)

## Підготовка середовища

```bash
# з кореня репозиторію, у віртуальному середовищі з ЛР №1
pip install -r requirements.txt
```

## Структура

```
labs/lab02/
├── main.py        # команди demo та analyze
├── task1.py       # User, Admin, Session, AuditLog, UserAccount
├── task2.py       # монітор сертифікатів (варіант 10)
├── README.md
└── data/
    └── data_v10/
        └── certificates.json   # 8 сертифікатів: domain, issuer, validFrom, validTo, keyLength, signatureAlgorithm
```

## Запуск

Завдання 1 (демонстрація ООП):

```bash
python -m labs.lab02.main demo
```

Завдання 2 (аналіз сертифікатів):

```bash
python -m labs.lab02.main analyze \
  --certs-data labs/lab02/data/data_v10/certificates.json \
  --days-warning 30 \
  --output-report labs/lab02/data/ssl_expiry_report.json \
  --format json
```

Відтворюваний запуск з фіксованою датою відліку (дані розраховані на 27.09.2026):

```bash
python -m labs.lab02.main analyze --certs-data labs/lab02/data/data_v10/certificates.json --today 2026-09-27
```

Також можна запускати окремо: `python -m labs.lab02.task2 --certs-data ...`

### CLI-параметри

| Параметр | Обов'язковий | Опис |
|---|---|---|
| `--certs-data` | так | JSON-файл з масивом сертифікатів |
| `--days-warning` | ні (30) | скільки днів до закінчення вважати попередженням |
| `--output-report` | ні | файл звіту; якщо не вказано — лише вивід у консоль |
| `--format` | ні (`json`) | формат звіту: `json` або `csv` |
| `--today` | ні | дата відліку `YYYY-MM-DD` (за замовч. сьогодні, UTC); потрібна для відтворюваності |

## Алгоритм

1. JSON читається через `pathlib` + `json`; записи без обов'язкових полів, з некоректним доменом (`re`) або датою пропускаються з `logging.warning`.
2. Кількість днів до закінчення: `valid_to - today` (різниця дат, `timedelta.days`).
3. Статус сертифіката:
   - `EXPIRED` — днів < 0;
   - `WARNING` — 0 ≤ днів ≤ `--days-warning`;
   - `WEAK` — термін ще не підходить до кінця, але застарілий алгоритм підпису (`re`: MD2/MD4/MD5/SHA-1) або RSA-ключ < 2048 біт;
   - `OK` — решта.
4. Видавці рахуються через `collections.Counter`.
5. Попередження — через `logging.warning`; помилки читання — `logging.error`, код завершення 1.

## Результат запуску (`--today 2026-09-27`)

```
[INFO] Audited 8 domain certificates (reference date 2026-09-27).

=== Certificate Expiry & Safety Status ===
Domain                        Issuer          Days Left  Status   Signature Alg
expired.example.invalid       DigiCert               -7  EXPIRED  sha256WithRSAEncryption
soon.example.invalid          Let's Encrypt          13  WARNING  sha256WithRSAEncryption
warning-edge.example.invalid  DigiCert               30  WARNING  sha256WithRSAEncryption
ok.example.invalid            Let's Encrypt          63  OK       sha256WithRSAEncryption
ecdsa.example.invalid         Sectigo                65  OK       ecdsa-with-SHA256
weak-sha1.example.invalid     Legacy CA              96  WEAK     sha1WithRSAEncryption
weak-md5.example.invalid      Legacy CA             127  WEAK     md5WithRSAEncryption
later.example.invalid         Sectigo               339  OK       sha384WithRSAEncryption

=== Issuer Statistics ===
Let's Encrypt  : 2
DigiCert       : 2
Legacy CA      : 2
Sectigo        : 2

[WARNING] 1 certificate(s) EXPIRED, 2 expiring within 30 days, 2 with weak crypto.
```

Пояснення знайдених аномалій: `expired` прострочений на 7 днів; `soon` та `warning-edge` потрапляють у вікно
30 днів; `weak-sha1` підписаний SHA-1, `weak-md5` — MD5 до того ж з RSA-ключем лише 1024 біти (обидва від
«Legacy CA»). `ecdsa` з ключем 256 біт — нормальний, бо вимога ≥ 2048 стосується лише RSA.
З сьогоднішньою датою результат інший (`soon` уже прострочений), бо термін спливає з часом.

## Ruff

```bash
ruff check .
ruff format --check .
```

Результат: _(вставити вивід після запуску)_

## Репозиторій

Посилання: _(вставити)_; коміт: `git add . && git commit -m "feat: complete lab02 tasks" && git push`
