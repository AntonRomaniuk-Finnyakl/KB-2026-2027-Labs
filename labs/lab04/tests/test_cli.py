import json
from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import main as cli
from labs.lab04.api_client import UnexpectedStatusError
from labs.lab04.tests.conftest import SAMPLE_PATH

CVE = "CVE-2099-10001"


@pytest.fixture
def no_network(monkeypatch):
    fake = Mock(side_effect=AssertionError("мережевий запит заборонено"))
    monkeypatch.setattr(cli, "fetch_response", fake)
    return fake


def run(capsys, *argv):
    code = cli.main(list(argv))
    captured = capsys.readouterr()
    return code, captured.out, captured.err


# --- локальний режим ---


def test_local_run_variant_10(capsys, no_network):
    code, out, err = run(capsys, "--cve", CVE, "--input", str(SAMPLE_PATH))
    assert code == 0
    assert err == ""
    report = json.loads(out)
    assert report["variant"] == 10
    assert report["decision"] == "other"
    assert report["observed"] == "NONE"
    assert report["rule"] == {
        "threshold": 6.0,
        "field": "privilegesRequired",
        "expected": "LOW",
    }
    no_network.assert_not_called()


def test_local_run_variant_1_matches_lab_example(monkeypatch, capsys, no_network):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", 1)
    code, out, _ = run(capsys, "--cve", CVE, "--input", str(SAMPLE_PATH))
    assert code == 0
    assert json.loads(out) == {
        "cve_id": CVE,
        "variant": 1,
        "description": "Synthetic vulnerability for offline API testing.",
        "vuln_status": "Analyzed",
        "cvss_version": "3.1",
        "score": 9.8,
        "score_source": "nvd@nist.gov",
        "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "rule": {"threshold": 7.0, "field": "attackVector", "expected": "NETWORK"},
        "observed": "NETWORK",
        "decision": "review",
    }


def test_non_ascii_is_not_escaped(tmp_path, capsys):
    payload = json.loads(SAMPLE_PATH.read_text(encoding="utf-8"))
    payload["vulnerabilities"][0]["cve"]["descriptions"][0]["value"] = "Опис ЇЄ"
    path = tmp_path / "ua.json"
    path.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    code, out, _ = run(capsys, "--cve", CVE, "--input", str(path))
    assert code == 0
    assert "Опис ЇЄ" in out


def test_local_not_found_exit_code_0(tmp_path, capsys):
    path = tmp_path / "empty.json"
    path.write_text('{"vulnerabilities": []}', encoding="utf-8")
    code, out, err = run(capsys, "--cve", CVE, "--input", str(path))
    assert code == 0
    assert err == ""
    assert json.loads(out)["decision"] == "not_found"


def test_local_cve_mismatch_is_error(capsys):
    code, out, err = run(capsys, "--cve", "CVE-2099-99999", "--input", str(SAMPLE_PATH))
    assert code == 1
    assert out == ""
    assert "Помилка" in err


def test_invalid_json_file(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    code, out, err = run(capsys, "--cve", CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "JSON" in err
    assert "Traceback" not in err


def test_missing_file(tmp_path, capsys):
    code, out, err = run(capsys, "--cve", CVE, "--input", str(tmp_path / "none.json"))
    assert code == 1
    assert out == ""
    assert "файл" in err


def test_non_utf8_file(tmp_path, capsys):
    path = tmp_path / "latin.json"
    path.write_bytes(b'{"a": "\xff\xfe"}')
    code, out, err = run(capsys, "--cve", CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "UTF-8" in err


def test_invalid_structure_in_file(tmp_path, capsys):
    path = tmp_path / "shape.json"
    path.write_text('{"vulnerabilities": "x"}', encoding="utf-8")
    code, out, err = run(capsys, "--cve", CVE, "--input", str(path))
    assert code == 1
    assert out == ""
    assert "некоректні дані" in err


def test_load_response_reads_json(tmp_path):
    path = tmp_path / "ok.json"
    path.write_text('{"a": "é"}', encoding="utf-8")
    assert cli.load_response(path) == {"a": "é"}


# --- мережевий режим (fetch_response підмінено) ---


def test_network_mode_uses_fetch(monkeypatch, capsys, sample_payload):
    fake = Mock(return_value=sample_payload)
    monkeypatch.setattr(cli, "fetch_response", fake)
    code, out, err = run(capsys, "--cve", CVE)
    assert code == 0
    assert err == ""
    assert json.loads(out)["decision"] == "other"
    fake.assert_called_once_with(CVE)


def make_http_error(status):
    response = Mock(spec=requests.Response)
    response.status_code = status
    return requests.exceptions.HTTPError("secret body", response=response)


@pytest.mark.parametrize(
    ("error", "fragment"),
    [
        (make_http_error(404), "404"),
        (make_http_error(503), "503"),
        (UnexpectedStatusError(302), "302"),
        (requests.exceptions.ConnectTimeout("t"), "очікування"),
        (requests.exceptions.ReadTimeout("t"), "очікування"),
        (requests.exceptions.ConnectionError("c"), "з'єднання"),
        (requests.exceptions.JSONDecodeError("Invalid JSON", "{", 1), "JSON"),
        (requests.exceptions.RequestException("other"), "запиту"),
    ],
)
def test_network_errors_exit_1(monkeypatch, capsys, error, fragment):
    monkeypatch.setattr(cli, "fetch_response", Mock(side_effect=error))
    code, out, err = run(capsys, "--cve", CVE)
    assert code == 1
    assert out == ""
    assert fragment in err
    assert "Traceback" not in err


def test_http_404_is_not_not_found(monkeypatch, capsys):
    monkeypatch.setattr(cli, "fetch_response", Mock(side_effect=make_http_error(404)))
    code, out, _ = run(capsys, "--cve", CVE)
    assert code == 1
    assert "not_found" not in out


def test_secrets_are_not_printed(monkeypatch, capsys):
    monkeypatch.setenv("NVD_API_KEY", "fake-secret-key")
    error = requests.exceptions.ConnectionError("apiKey=fake-secret-key failed")
    monkeypatch.setattr(cli, "fetch_response", Mock(side_effect=error))
    code, out, err = run(capsys, "--cve", CVE)
    assert code == 1
    assert "fake-secret-key" not in out + err
    assert "apiKey" not in out + err


# --- аргументи та номер варіанта ---


@pytest.mark.parametrize(
    "cve",
    [
        "cve-2099-10001",
        "CVE-99-10001",
        "CVE-2099-123",
        "CVE-2099-10001x",
        "CVE-2099-10001\n",
        "",
    ],
)
def test_invalid_cve_exits_2(capsys, no_network, cve):
    with pytest.raises(SystemExit) as info:
        cli.main(["--cve", cve])
    assert info.value.code == 2
    assert capsys.readouterr().out == ""


@pytest.mark.parametrize(
    "cve", ["CVE-2021-44228", "CVE-2099-10001", "CVE-1999-12345678"]
)
def test_valid_cve_formats(monkeypatch, capsys, cve):
    monkeypatch.setattr(
        cli, "fetch_response", Mock(return_value={"vulnerabilities": []})
    )
    assert cli.main(["--cve", cve]) == 0
    assert json.loads(capsys.readouterr().out)["cve_id"] == cve


def test_missing_cve_exits_2(capsys, no_network):
    with pytest.raises(SystemExit) as info:
        cli.main([])
    assert info.value.code == 2


@pytest.mark.parametrize("variant", [0, 16, -3, True, "10", 10.0, None])
def test_invalid_variant_exits_2(monkeypatch, capsys, no_network, variant):
    monkeypatch.setattr(cli, "VARIANT_NUMBER", variant)
    code, out, err = run(capsys, "--cve", CVE)
    assert code == 2
    assert out == ""
    assert "варіанта" in err
    no_network.assert_not_called()
