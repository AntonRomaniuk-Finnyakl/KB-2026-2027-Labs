"""Перевірка відповіді NVD і правило варіанта (без введення-виведення)."""

import math
from typing import Any


def _ensure(condition: bool, message: str) -> None:
    """Підняти ValueError, якщо умова контракту не виконується."""
    if not condition:
        raise ValueError(message)


# Допустимі значення полів cvssData (розділ 2.2 завдання).
ALLOWED_VALUES: dict[str, frozenset[str]] = {
    "attackVector": frozenset({"NETWORK", "ADJACENT_NETWORK", "LOCAL", "PHYSICAL"}),
    "attackComplexity": frozenset({"LOW", "HIGH"}),
    "privilegesRequired": frozenset({"NONE", "LOW", "HIGH"}),
    "userInteraction": frozenset({"NONE", "REQUIRED"}),
    "scope": frozenset({"UNCHANGED", "CHANGED"}),
    "confidentialityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "integrityImpact": frozenset({"NONE", "LOW", "HIGH"}),
    "availabilityImpact": frozenset({"NONE", "LOW", "HIGH"}),
}

# Варіант -> (поріг, поле, очікуване значення).
RULES: dict[int, tuple[float, str, str]] = {
    1: (7.0, "attackVector", "NETWORK"),
    2: (8.0, "attackComplexity", "LOW"),
    3: (7.0, "privilegesRequired", "NONE"),
    4: (8.0, "userInteraction", "NONE"),
    5: (7.0, "confidentialityImpact", "HIGH"),
    6: (7.0, "integrityImpact", "HIGH"),
    7: (7.0, "availabilityImpact", "HIGH"),
    8: (9.0, "scope", "CHANGED"),
    9: (5.0, "attackVector", "LOCAL"),
    10: (6.0, "privilegesRequired", "LOW"),
    11: (6.0, "userInteraction", "REQUIRED"),
    12: (6.0, "confidentialityImpact", "LOW"),
    13: (6.0, "integrityImpact", "LOW"),
    14: (6.0, "availabilityImpact", "LOW"),
    15: (8.0, "attackComplexity", "HIGH"),
}


def _optional_str(container: dict[str, Any], key: str, name: str) -> str | None:
    """Повернути непорожній рядок за ключем або None, якщо ключа немає."""
    if key not in container:
        return None
    value = container[key]
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"Поле {name} має бути непорожнім рядком")
    return value


def _pick_description(cve: dict[str, Any]) -> str | None:
    """Повернути перший непорожній англійський опис або None."""
    if "descriptions" not in cve:
        return None
    descriptions = cve["descriptions"]
    _ensure(isinstance(descriptions, list), "Поле descriptions має бути списком")
    chosen = None
    for item in descriptions:
        _ensure(
            isinstance(item, dict)
            and isinstance(item.get("lang"), str)
            and isinstance(item.get("value"), str),
            "Елемент descriptions має містити рядки lang і value",
        )
        if chosen is None and item["lang"] == "en" and item["value"].strip():
            chosen = item["value"]
    return chosen


def _select_metric(cve: dict[str, Any]) -> dict[str, Any] | None:
    """Вибрати оцінку CVSS v3.1 (перший Primary, інакше перший елемент)."""
    if "metrics" not in cve:
        return None
    metrics = cve["metrics"]
    _ensure(isinstance(metrics, dict), "Поле metrics має бути об'єктом")
    if "cvssMetricV31" not in metrics:
        return None
    entries = metrics["cvssMetricV31"]
    _ensure(isinstance(entries, list), "Поле cvssMetricV31 має бути списком")
    if not entries:
        return None
    if not all(isinstance(entry, dict) for entry in entries):
        raise ValueError("Елементи cvssMetricV31 мають бути об'єктами")
    for entry in entries:
        if entry.get("type") == "Primary":
            return entry
    return entries[0]


def _build_cvss(entry: dict[str, Any]) -> dict[str, Any]:
    """Перевірити вибрану оцінку й зібрати її внутрішнє подання."""
    data = entry.get("cvssData")
    _ensure(isinstance(data, dict), "Поле cvssData має бути об'єктом")
    score = data.get("baseScore")
    if (
        isinstance(score, bool)
        or not isinstance(score, (int, float))
        or not math.isfinite(score)
        or not 0 <= score <= 10
    ):
        raise ValueError("baseScore має бути скінченним числом від 0 до 10")
    version = _optional_str(data, "version", "cvssData.version")
    if version is not None and version != "3.1":
        raise ValueError("Версія CVSS має бути 3.1")
    return {
        "score": score,
        "source": _optional_str(entry, "source", "source"),
        "version": version,
        "vector": _optional_str(data, "vectorString", "cvssData.vectorString"),
        "data": dict(data),
    }


def extract_record(payload: Any, cve_id: str) -> dict[str, Any] | None:
    """Перевірити відповідь NVD і повернути внутрішній запис або None.

    Внутрішній запис — словник із ключами:
      vuln_status: str | None — статус NVD;
      description: str | None — перший непорожній англійський опис;
      cvss: None або словник {score, source, version, vector, data}, де
        data — копія cvssData вибраної оцінки (для перевірки поля варіанта).
    cvss дорівнює None для Rejected, відсутнього статусу або відсутньої оцінки.
    Повертає None, якщо запис не знайдено; ValueError — за порушення структури.
    """
    _ensure(isinstance(payload, dict), "Відповідь має бути JSON-об'єктом")
    vulnerabilities = payload.get("vulnerabilities")
    _ensure(isinstance(vulnerabilities, list), "Поле vulnerabilities має бути списком")
    if len(vulnerabilities) > 1:
        _ensure(False, "Для точного cveId очікується не більше одного запису")
    if not vulnerabilities:
        return None
    item = vulnerabilities[0]
    _ensure(
        isinstance(item, dict) and isinstance(item.get("cve"), dict),
        "Елемент vulnerabilities має містити об'єкт cve",
    )
    cve = item["cve"]
    if cve.get("id") != cve_id:
        raise ValueError("Ідентифікатор у відповіді не збігається із запитаним")

    status = _optional_str(cve, "vulnStatus", "vulnStatus")
    description = _pick_description(cve)
    cvss = None
    if status is not None and status != "Rejected":
        entry = _select_metric(cve)
        if entry is not None:
            cvss = _build_cvss(entry)
    return {"vuln_status": status, "description": description, "cvss": cvss}


def build_report(
    record: dict[str, Any] | None, cve_id: str, variant: int
) -> dict[str, Any]:
    """Застосувати правило варіанта до внутрішнього запису й повернути звіт."""
    if (
        isinstance(variant, bool)
        or not isinstance(variant, int)
        or variant not in RULES
    ):
        raise ValueError("Номер варіанта має бути цілим числом від 1 до 15")
    threshold, field, expected = RULES[variant]
    report: dict[str, Any] = {
        "cve_id": cve_id,
        "variant": variant,
        "description": None,
        "vuln_status": None,
        "cvss_version": None,
        "score": None,
        "score_source": None,
        "vector": None,
        "rule": {"threshold": threshold, "field": field, "expected": expected},
        "observed": None,
        "decision": "not_found",
    }
    if record is None:
        return report

    report["description"] = record["description"]
    report["vuln_status"] = record["vuln_status"]
    if record["vuln_status"] == "Rejected":
        report["decision"] = "rejected"
        return report
    cvss = record["cvss"]
    if record["vuln_status"] is None or cvss is None:
        report["decision"] = "insufficient_data"
        return report

    report["cvss_version"] = cvss["version"]
    report["score"] = cvss["score"]
    report["score_source"] = cvss["source"]
    report["vector"] = cvss["vector"]
    data = cvss["data"]
    if field not in data:
        report["decision"] = "insufficient_data"
        return report
    observed = data[field]
    if not isinstance(observed, str) or observed not in ALLOWED_VALUES[field]:
        raise ValueError(f"Поле {field} має недопустиме значення")
    report["observed"] = observed
    is_review = cvss["score"] >= threshold and observed == expected
    report["decision"] = "review" if is_review else "other"
    return report
