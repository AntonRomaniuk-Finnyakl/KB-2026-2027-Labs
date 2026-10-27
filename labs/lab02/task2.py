"""Завдання 2 (варіант 10): монітор термінів дії SSL/TLS сертифікатів."""

from __future__ import annotations

import argparse
import csv
import json
import logging
import re
import sys
from collections import Counter
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from pathlib import Path

logger = logging.getLogger("cert_monitor")

DOMAIN_RE = re.compile(
    r"^(?:\*\.)?(?:[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?\.)+[A-Za-z]{2,63}$"
)
# Застарілі алгоритми підпису: MD2/MD4/MD5/SHA-1 (у т.ч. "ecdsa-with-SHA1")
WEAK_SIG_RE = re.compile(
    r"^(?:md[245]|sha-?1)(?![0-9])|-with-(?:sha-?1|md[245])$", re.IGNORECASE
)
MIN_RSA_KEY_BITS = 2048
REQUIRED_FIELDS = ("domain", "issuer", "validFrom", "validTo", "keyLength")


@dataclass
class Certificate:
    """Сертифікат вузла."""

    domain: str
    issuer: str
    valid_from: date
    valid_to: date
    key_length: int
    signature_alg: str = ""


@dataclass
class CertReport:
    """Результат перевірки одного сертифіката."""

    domain: str
    issuer: str
    valid_to: str
    days_left: int
    status: str
    signature_alg: str
    key_length: int
    issues: list[str] = field(default_factory=list)


def parse_certificates(path: Path) -> list[Certificate]:
    """Прочитати JSON-масив сертифікатів; некоректні записи пропускаються."""
    with path.open(encoding="utf-8") as fh:
        data = json.load(fh)
    if not isinstance(data, list):
        raise TypeError("JSON root must be a list of certificates")
    certs: list[Certificate] = []
    for idx, item in enumerate(data, start=1):
        try:
            missing = [k for k in REQUIRED_FIELDS if k not in item]
            if missing:
                raise ValueError(f"missing fields: {', '.join(missing)}")
            if not DOMAIN_RE.match(str(item["domain"])):
                raise ValueError(f"invalid domain {item['domain']!r}")
            cert = Certificate(
                domain=item["domain"],
                issuer=str(item["issuer"]),
                valid_from=date.fromisoformat(item["validFrom"]),
                valid_to=date.fromisoformat(item["validTo"]),
                key_length=int(item["keyLength"]),
                signature_alg=str(item.get("signatureAlgorithm", "")),
            )
            if cert.valid_to < cert.valid_from:
                raise ValueError("validTo is earlier than validFrom")
        except (ValueError, TypeError) as exc:
            logger.warning("Entry #%d skipped: %s", idx, exc)
            continue
        certs.append(cert)
    return certs


def check_certificate(cert: Certificate, today: date, days_warning: int) -> CertReport:
    """Оцінити сертифікат: термін дії, алгоритм підпису, довжина ключа."""
    days_left = (cert.valid_to - today).days  # різниця дат (timedelta.days)
    issues: list[str] = []
    if days_left < 0:
        status = "EXPIRED"
        issues.append(f"expired {-days_left} days ago")
    elif days_left <= days_warning:
        status = "WARNING"
        issues.append(f"expires in {days_left} days")
    else:
        status = "OK"
    if WEAK_SIG_RE.search(cert.signature_alg):
        issues.append(f"weak signature algorithm {cert.signature_alg}")
    if "rsa" in cert.signature_alg.lower() and cert.key_length < MIN_RSA_KEY_BITS:
        issues.append(f"weak RSA key ({cert.key_length} bit)")
    if status == "OK" and len(issues) > 0:
        status = "WEAK"
    return CertReport(
        cert.domain,
        cert.issuer,
        cert.valid_to.isoformat(),
        days_left,
        status,
        cert.signature_alg,
        cert.key_length,
        issues,
    )


def write_report(
    path: Path, reports: list[CertReport], issuers: Counter[str], fmt: str
) -> None:
    """Зберегти звіт у JSON або CSV."""
    path.parent.mkdir(parents=True, exist_ok=True)
    if fmt == "json":
        payload = {
            "issuers": dict(issuers),
            "certificates": [asdict(r) for r in reports],
        }
        path.write_text(
            json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8"
        )
        return
    with path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(
            [
                "Domain",
                "Issuer",
                "ValidTo",
                "DaysLeft",
                "Status",
                "SignatureAlg",
                "KeyLength",
                "Issues",
            ]
        )
        for r in reports:
            writer.writerow(
                [
                    r.domain,
                    r.issuer,
                    r.valid_to,
                    r.days_left,
                    r.status,
                    r.signature_alg,
                    r.key_length,
                    "; ".join(r.issues),
                ]
            )


def add_arguments(parser: argparse.ArgumentParser) -> None:
    """Додати CLI-аргументи варіанта 10."""
    parser.add_argument(
        "--certs-data", type=Path, required=True, help="JSON-файл із сертифікатами"
    )
    parser.add_argument(
        "--days-warning",
        type=int,
        default=30,
        help="поріг попередження, днів (за замовч. 30)",
    )
    parser.add_argument("--output-report", type=Path, default=None, help="файл звіту")
    parser.add_argument(
        "--format",
        choices=("json", "csv"),
        default="json",
        help="формат звіту (за замовч. json)",
    )
    parser.add_argument(
        "--today",
        type=date.fromisoformat,
        default=None,
        help="дата відліку YYYY-MM-DD (для тестів)",
    )


def run(args: argparse.Namespace) -> int:
    """Виконати перевірку; повертає код завершення процесу."""
    if args.days_warning < 0:
        logger.error("--days-warning must be >= 0")
        return 2
    today = args.today or datetime.now(UTC).date()
    try:
        logger.info("Loading SSL certificates data from %s...", args.certs_data)
        certs = parse_certificates(args.certs_data)
    except (
        OSError,
        ValueError,
        TypeError,
    ) as exc:  # json.JSONDecodeError є підкласом ValueError
        logger.error("Cannot read input: %s", exc)
        return 1
    logger.info(
        "Audited %d domain certificates (reference date %s).", len(certs), today
    )

    reports = sorted(
        (check_certificate(c, today, args.days_warning) for c in certs),
        key=lambda r: r.days_left,
    )
    issuers: Counter[str] = Counter(c.issuer for c in certs)

    print("\n=== Certificate Expiry & Safety Status ===")
    print(f"{'Domain':<30}{'Issuer':<15}{'Days Left':>10}  {'Status':<8} Signature Alg")
    for r in reports:
        print(
            f"{r.domain:<30}{r.issuer:<15}{r.days_left:>10}  {r.status:<8} {r.signature_alg}"
        )
        for issue in r.issues:
            if r.status != "OK":
                logger.warning("%s: %s", r.domain, issue)

    print("\n=== Issuer Statistics ===")
    for issuer, count in issuers.most_common():
        print(f"{issuer:<15}: {count}")

    stats = Counter(r.status for r in reports)
    if stats["EXPIRED"] or stats["WARNING"] or stats["WEAK"]:
        logger.warning(
            "%d certificate(s) EXPIRED, %d expiring within %d days, %d with weak crypto.",
            stats["EXPIRED"],
            stats["WARNING"],
            args.days_warning,
            stats["WEAK"],
        )
    if args.output_report:
        write_report(args.output_report, reports, issuers, args.format)
        logger.info("Report saved to %s", args.output_report)
    return 0


def main(argv: list[str] | None = None) -> int:
    """Автономний запуск: python -m labs.lab02.task2 --certs-data ..."""
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    parser = argparse.ArgumentParser(
        description="SSL/TLS certificate expiry monitor (variant 10)"
    )
    add_arguments(parser)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    sys.exit(main())
