import copy
import json
from pathlib import Path
from typing import Any

import pytest

SAMPLE_PATH = Path(__file__).resolve().parents[1] / "data" / "nvd_sample.json"
MISSING = object()
CVE_ID = "CVE-2099-10001"


@pytest.fixture(autouse=True)
def isolated_environment(monkeypatch):
    monkeypatch.delenv("NVD_API_KEY", raising=False)
    monkeypatch.delattr("requests.sessions.Session.request")


@pytest.fixture
def sample_payload() -> dict[str, Any]:
    """Нова копія синтетичної відповіді для кожного тесту."""
    return json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))


def make_entry(
    score: Any = 7.0, source: Any = "nvd@nist.gov", type_: Any = "Primary", **data: Any
) -> dict[str, Any]:
    """Елемент cvssMetricV31; MISSING у data видаляє ключ."""
    cvss_data: dict[str, Any] = {
        "version": "3.1",
        "vectorString": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "attackVector": "NETWORK",
        "attackComplexity": "LOW",
        "privilegesRequired": "LOW",
        "userInteraction": "NONE",
        "scope": "UNCHANGED",
        "confidentialityImpact": "HIGH",
        "integrityImpact": "HIGH",
        "availabilityImpact": "HIGH",
        "baseScore": score,
        "baseSeverity": "HIGH",
    }
    cvss_data.update(data)
    cvss_data = {k: v for k, v in cvss_data.items() if v is not MISSING}
    entry = {"source": source, "type": type_, "cvssData": cvss_data}
    return {k: v for k, v in entry.items() if v is not MISSING}


def make_payload(
    entries: Any = MISSING,
    status: Any = "Analyzed",
    cve_id: str = CVE_ID,
    descriptions: Any = MISSING,
    metrics: Any = MISSING,
) -> dict[str, Any]:
    """Відповідь NVD з одним записом; MISSING означає відсутній ключ."""
    cve: dict[str, Any] = {"id": cve_id}
    if status is not MISSING:
        cve["vulnStatus"] = status
    if descriptions is MISSING:
        descriptions = [{"lang": "en", "value": "Test description."}]
    cve["descriptions"] = descriptions
    if metrics is not MISSING:
        cve["metrics"] = metrics
    elif entries is not MISSING:
        cve["metrics"] = {"cvssMetricV31": entries}
    return {"vulnerabilities": [{"cve": cve}]}


@pytest.fixture
def entry_factory():
    return make_entry


@pytest.fixture
def payload_factory():
    return make_payload


@pytest.fixture
def deep_copy():
    return copy.deepcopy
