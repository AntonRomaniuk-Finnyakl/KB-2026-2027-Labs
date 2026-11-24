import copy
import math

import pytest

from labs.lab04.analysis import build_report, extract_record
from labs.lab04.tests.conftest import CVE_ID, MISSING, make_entry, make_payload

VARIANT = 10  # privilegesRequired == LOW, поріг 6.0

REPORT_KEYS = {
    "cve_id", "variant", "description", "vuln_status", "cvss_version", "score",
    "score_source", "vector", "rule", "observed", "decision",
}  # fmt: skip


def report_for(payload, variant=VARIANT):
    return build_report(extract_record(payload, CVE_ID), CVE_ID, variant)


# --- правило варіанта: поріг і ознака ---


@pytest.mark.parametrize(
    ("score", "privileges", "expected"),
    [
        (5.9, "LOW", "other"),
        (6.0, "LOW", "review"),
        (6.1, "LOW", "review"),
        (10, "LOW", "review"),
        (0.0, "LOW", "other"),
        (9.8, "NONE", "other"),
        (9.8, "HIGH", "other"),
        (6.0, "NONE", "other"),
    ],
)
def test_variant_10_rule(score, privileges, expected):
    payload = make_payload([make_entry(score, privilegesRequired=privileges)])
    assert report_for(payload)["decision"] == expected


def test_review_report_contents():
    payload = make_payload([make_entry(6.0)])
    report = report_for(payload)
    assert set(report) == REPORT_KEYS
    assert report["rule"] == {
        "threshold": 6.0,
        "field": "privilegesRequired",
        "expected": "LOW",
    }
    assert report["observed"] == "LOW"
    assert report["score"] == 6.0
    assert report["score_source"] == "nvd@nist.gov"
    assert report["cvss_version"] == "3.1"
    assert report["vuln_status"] == "Analyzed"
    assert report["description"] == "Test description."


# Незалежна таблиця: варіант -> (поріг, поле, очікуване значення).
ALL_RULES = [
    (1, 7.0, "attackVector", "NETWORK"),
    (2, 8.0, "attackComplexity", "LOW"),
    (3, 7.0, "privilegesRequired", "NONE"),
    (4, 8.0, "userInteraction", "NONE"),
    (5, 7.0, "confidentialityImpact", "HIGH"),
    (6, 7.0, "integrityImpact", "HIGH"),
    (7, 7.0, "availabilityImpact", "HIGH"),
    (8, 9.0, "scope", "CHANGED"),
    (9, 5.0, "attackVector", "LOCAL"),
    (10, 6.0, "privilegesRequired", "LOW"),
    (11, 6.0, "userInteraction", "REQUIRED"),
    (12, 6.0, "confidentialityImpact", "LOW"),
    (13, 6.0, "integrityImpact", "LOW"),
    (14, 6.0, "availabilityImpact", "LOW"),
    (15, 8.0, "attackComplexity", "HIGH"),
]


@pytest.mark.parametrize(("variant", "threshold", "field", "value"), ALL_RULES)
def test_all_variants_threshold(variant, threshold, field, value):
    at = make_payload([make_entry(threshold, **{field: value})])
    below = make_payload([make_entry(threshold - 0.1, **{field: value})])
    assert report_for(at, variant)["decision"] == "review"
    assert report_for(below, variant)["decision"] == "other"


# --- стани not_found / rejected / insufficient_data ---


def test_not_found():
    report = report_for({"vulnerabilities": []})
    assert report["decision"] == "not_found"
    assert report["cve_id"] == CVE_ID
    assert report["variant"] == VARIANT
    assert report["rule"]["field"] == "privilegesRequired"
    for key in REPORT_KEYS - {"cve_id", "variant", "rule", "decision"}:
        assert report[key] is None


def test_rejected_ignores_high_score():
    payload = make_payload([make_entry(9.8)], status="Rejected")
    report = report_for(payload)
    assert report["decision"] == "rejected"
    assert report["vuln_status"] == "Rejected"
    assert report["description"] == "Test description."
    for key in ("score", "score_source", "vector", "cvss_version", "observed"):
        assert report[key] is None


def test_rejected_does_not_validate_scores():
    payload = make_payload([make_entry("bad")], status="Rejected")
    assert report_for(payload)["decision"] == "rejected"


def test_missing_status_is_insufficient_data():
    payload = make_payload([make_entry(9.8)], status=MISSING)
    report = report_for(payload)
    assert report["decision"] == "insufficient_data"
    assert report["vuln_status"] is None
    assert report["score"] is None
    assert report["observed"] is None
    assert report["description"] == "Test description."


@pytest.mark.parametrize(
    "kwargs",
    [
        {},  # немає metrics
        {"metrics": {}},  # немає cvssMetricV31
        {"entries": []},  # порожній список
        {"metrics": {"cvssMetricV30": [{"cvssData": {"baseScore": 9.8}}]}},
    ],
)
def test_missing_score_is_insufficient_data(kwargs):
    report = report_for(make_payload(**kwargs))
    assert report["decision"] == "insufficient_data"
    assert report["score"] is None
    assert report["vuln_status"] == "Analyzed"


def test_missing_rule_field_is_insufficient_data():
    payload = make_payload([make_entry(9.8, privilegesRequired=MISSING)])
    report = report_for(payload)
    assert report["decision"] == "insufficient_data"
    assert report["score"] == 9.8
    assert report["observed"] is None


# --- помилки даних ---


@pytest.mark.parametrize("bad", [None, "", "HIGHEST", "low", 1, ["LOW"]])
def test_bad_rule_field_raises(bad):
    payload = make_payload([make_entry(9.8, privilegesRequired=bad)])
    with pytest.raises(ValueError):
        report_for(payload)


@pytest.mark.parametrize(
    "bad_score",
    ["9.8", True, False, None, math.nan, math.inf, -math.inf, -0.1, 10.1, [], {}],
)
def test_bad_base_score_raises(bad_score):
    payload = make_payload([make_entry(bad_score)])
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_missing_base_score_raises():
    payload = make_payload([make_entry(MISSING)])
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


def test_missing_cvss_data_raises():
    payload = make_payload([{"source": "x", "type": "Primary"}])
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize(
    "payload",
    [
        [],
        "text",
        None,
        {},
        {"vulnerabilities": None},
        {"vulnerabilities": {}},
        {"vulnerabilities": [{}]},
        {"vulnerabilities": [{"cve": None}]},
        {"vulnerabilities": [{"cve": {"id": "CVE-2099-99999"}}]},
        {"vulnerabilities": [{"cve": {"id": CVE_ID}}, {"cve": {"id": CVE_ID}}]},
    ],
)
def test_bad_structure_raises(payload):
    with pytest.raises(ValueError):
        extract_record(payload, CVE_ID)


@pytest.mark.parametrize("status", [None, "", "  ", 5, []])
def test_bad_status_raises(status):
    with pytest.raises(ValueError):
        extract_record(make_payload(status=status), CVE_ID)


@pytest.mark.parametrize(
    "descriptions",
    [None, "text", ["text"], [{"lang": "en"}], [{"lang": 1, "value": "x"}]],
)
def test_bad_descriptions_raise(descriptions):
    with pytest.raises(ValueError):
        extract_record(make_payload(descriptions=descriptions), CVE_ID)


@pytest.mark.parametrize("metrics", [None, [], "x"])
def test_bad_metrics_raise(metrics):
    with pytest.raises(ValueError):
        extract_record(make_payload(metrics=metrics), CVE_ID)


@pytest.mark.parametrize("v31", [None, {}, "x"])
def test_bad_cvss_list_raises(v31):
    with pytest.raises(ValueError):
        extract_record(make_payload(metrics={"cvssMetricV31": v31}), CVE_ID)


def test_non_dict_entry_raises():
    with pytest.raises(ValueError):
        extract_record(make_payload(["text"]), CVE_ID)


@pytest.mark.parametrize("version", ["3.0", "", None, 3.1])
def test_bad_version_raises(version):
    with pytest.raises(ValueError):
        extract_record(make_payload([make_entry(version=version)]), CVE_ID)


def test_missing_version_and_vector_become_none():
    payload = make_payload([make_entry(6.0, version=MISSING, vectorString=MISSING)])
    report = report_for(payload)
    assert report["cvss_version"] is None
    assert report["vector"] is None
    assert report["decision"] == "review"


@pytest.mark.parametrize("vector", [None, "", 5])
def test_bad_vector_raises(vector):
    with pytest.raises(ValueError):
        extract_record(make_payload([make_entry(vectorString=vector)]), CVE_ID)


@pytest.mark.parametrize("variant", [0, 16, -1, True, 1.0, "10", None])
def test_bad_variant_raises(variant):
    with pytest.raises(ValueError):
        build_report(None, CVE_ID, variant)


# --- вибір оцінки ---


def test_primary_wins_over_earlier_secondary():
    payload = make_payload(
        [
            make_entry(9.9, source="secondary@example.invalid", type_="Secondary"),
            make_entry(6.0, source="nvd@nist.gov", type_="Primary"),
        ]
    )
    report = report_for(payload)
    assert report["score"] == 6.0
    assert report["score_source"] == "nvd@nist.gov"


def test_first_entry_used_without_primary():
    payload = make_payload(
        [
            make_entry(6.5, source="first@example.invalid", type_="Secondary"),
            make_entry(9.9, source="second@example.invalid", type_="Secondary"),
        ]
    )
    report = report_for(payload)
    assert report["score"] == 6.5
    assert report["score_source"] == "first@example.invalid"


def test_rule_uses_field_from_same_entry():
    payload = make_payload(
        [
            make_entry(9.0, type_="Secondary", privilegesRequired="LOW"),
            make_entry(9.0, type_="Primary", privilegesRequired="NONE"),
        ]
    )
    assert report_for(payload)["decision"] == "other"


def test_missing_source_becomes_none():
    payload = make_payload([make_entry(6.0, source=MISSING)])
    assert report_for(payload)["score_source"] is None


# --- описи ---


def test_description_selection():
    descriptions = [
        {"lang": "es", "value": "Descripción"},
        {"lang": "en", "value": "   "},
        {"lang": "en", "value": "First English."},
        {"lang": "en", "value": "Second English."},
    ]
    record = extract_record(make_payload(descriptions=descriptions), CVE_ID)
    assert record["description"] == "First English."


def test_no_english_description_is_none():
    descriptions = [{"lang": "es", "value": "Descripción"}]
    record = extract_record(make_payload(descriptions=descriptions), CVE_ID)
    assert record["description"] is None


def test_missing_descriptions_is_none():
    payload = make_payload()
    del payload["vulnerabilities"][0]["cve"]["descriptions"]
    assert extract_record(payload, CVE_ID)["description"] is None


# --- чистота функцій ---


def test_payload_is_not_mutated(sample_payload):
    before = copy.deepcopy(sample_payload)
    report_for(sample_payload)
    assert sample_payload == before


def test_sample_payload_variant_10(sample_payload):
    report = report_for(sample_payload)
    assert report["decision"] == "other"
    assert report["observed"] == "NONE"
    assert report["score"] == 9.8


@pytest.mark.parametrize(
    ("variant", "expected"),
    [(v, "review" if v <= 7 else "other") for v in range(1, 16)],
)
def test_sample_payload_all_variants(sample_payload, variant, expected):
    assert report_for(sample_payload, variant)["decision"] == expected
