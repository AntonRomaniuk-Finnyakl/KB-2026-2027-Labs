"""CLI-утиліта перегляду запису про вразливість із NVD (ЛР №4)."""

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Any

import requests

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.api_client import UnexpectedStatusError, fetch_response
from shared.student import VARIANT_NUMBER

CVE_PATTERN = re.compile(r"CVE-[0-9]{4}-[0-9]{4,}")


def _cve_type(value: str) -> str:
    """Перевірити повний збіг ідентифікатора з шаблоном CVE."""
    if CVE_PATTERN.fullmatch(value) is None:
        raise argparse.ArgumentTypeError("очікується формат CVE-РРРР-NNNN")
    return value


def build_parser() -> argparse.ArgumentParser:
    """Створити парсер аргументів командного рядка."""
    parser = argparse.ArgumentParser(
        prog="labs.lab04.main",
        description="Перегляд запису про вразливість у NVD (ЛР №4).",
    )
    parser.add_argument(
        "--cve", required=True, type=_cve_type, help="ідентифікатор CVE"
    )
    parser.add_argument(
        "--input",
        type=Path,
        default=None,
        help="локальний JSON-файл відповіді NVD (без мережевих запитів)",
    )
    return parser


def load_response(path: Path | str) -> Any:
    """Прочитати UTF-8 JSON-файл із відповіддю NVD."""
    text = Path(path).read_text(encoding="utf-8")
    return json.loads(text)


def _error(message: str) -> None:
    print(f"Помилка: {message}", file=sys.stderr)


def _is_valid_variant(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 1 <= value <= 15


def _obtain_payload(args: argparse.Namespace) -> Any:
    if args.input is not None:
        return load_response(args.input)
    return fetch_response(args.cve)


def main(argv: list[str] | None = None) -> int:
    """Запустити утиліту й повернути код завершення (0, 1 або 2)."""
    if not _is_valid_variant(VARIANT_NUMBER):
        _error("номер варіанта у shared/student.py має бути цілим числом від 1 до 15.")
        return 2
    args = build_parser().parse_args(argv)

    try:
        payload = _obtain_payload(args)
    except requests.exceptions.HTTPError as exc:
        status = getattr(exc.response, "status_code", None)
        suffix = f" (код {status})" if status is not None else ""
        _error(f"NVD повернув HTTP-помилку{suffix}.")
        return 1
    except UnexpectedStatusError as exc:
        _error(f"NVD повернув неочікуваний статус {exc.status_code}.")
        return 1
    except requests.exceptions.Timeout:
        _error("перевищено час очікування відповіді NVD.")
        return 1
    except requests.exceptions.ConnectionError:
        _error("не вдалося встановити з'єднання з NVD.")
        return 1
    except requests.exceptions.JSONDecodeError:
        _error("відповідь NVD не є коректним JSON.")
        return 1
    except requests.exceptions.RequestException:
        _error("під час запиту до NVD сталася помилка.")
        return 1
    except json.JSONDecodeError:
        _error("файл не містить коректного JSON.")
        return 1
    except UnicodeDecodeError:
        _error("файл не є коректним UTF-8.")
        return 1
    except OSError:
        _error("не вдалося прочитати файл.")
        return 1

    try:
        record = extract_record(payload, args.cve)
        report = build_report(record, args.cve, VARIANT_NUMBER)
    except ValueError as exc:
        _error(f"некоректні дані: {exc}")
        return 1

    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
