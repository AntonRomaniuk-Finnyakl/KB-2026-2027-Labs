from unittest.mock import Mock

import pytest
import requests

from labs.lab04 import api_client

URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def make_response(status=200, payload=None):
    response = Mock(spec=requests.Response)
    response.status_code = status
    response.headers = {"Content-Type": "application/json; charset=utf-8"}
    response.json.return_value = payload
    return response


def patch_get(monkeypatch, response=None, side_effect=None):
    fake_get = Mock(return_value=response, side_effect=side_effect)
    monkeypatch.setattr(api_client.requests, "get", fake_get)
    return fake_get


def test_fetch_uses_expected_request(monkeypatch):
    payload = {"startIndex": 0, "totalResults": 0, "vulnerabilities": []}
    response = make_response(200, payload)
    fake_get = patch_get(monkeypatch, response)

    assert api_client.fetch_response("CVE-2099-10001") == payload

    fake_get.assert_called_once_with(
        URL,
        params={"cveId": "CVE-2099-10001"},
        headers={"Accept": "application/json"},
        timeout=(3.05, 10),
        allow_redirects=False,
    )
    response.raise_for_status.assert_called_once_with()


def test_fetch_sends_api_key_header(monkeypatch):
    monkeypatch.setenv("NVD_API_KEY", "  fake-key-123  ")
    fake_get = patch_get(monkeypatch, make_response(200, {}))
    api_client.fetch_response("CVE-2099-10001")
    assert fake_get.call_args.kwargs["headers"] == {
        "Accept": "application/json",
        "apiKey": "fake-key-123",
    }


def test_build_headers_without_key():
    assert api_client.build_headers() == {"Accept": "application/json"}


@pytest.mark.parametrize("value", ["", "   ", "\t\n"])
def test_build_headers_blank_key_is_ignored(monkeypatch, value):
    monkeypatch.setenv("NVD_API_KEY", value)
    assert api_client.build_headers() == {"Accept": "application/json"}


def test_build_headers_reads_key_at_call_time(monkeypatch):
    assert "apiKey" not in api_client.build_headers()
    monkeypatch.setenv("NVD_API_KEY", "fake-key")
    assert api_client.build_headers()["apiKey"] == "fake-key"


def test_http_error_is_raised(monkeypatch):
    response = make_response(500)
    response.raise_for_status.side_effect = requests.exceptions.HTTPError(
        "500 Server Error", response=response
    )
    patch_get(monkeypatch, response)
    with pytest.raises(requests.exceptions.HTTPError):
        api_client.fetch_response("CVE-2099-10001")
    response.json.assert_not_called()


@pytest.mark.parametrize("status", [204, 301, 302])
def test_unexpected_status_is_rejected(monkeypatch, status):
    patch_get(monkeypatch, make_response(status))
    with pytest.raises(api_client.UnexpectedStatusError) as info:
        api_client.fetch_response("CVE-2099-10001")
    assert info.value.status_code == status


@pytest.mark.parametrize(
    "error",
    [
        requests.exceptions.ConnectTimeout("timeout"),
        requests.exceptions.ReadTimeout("timeout"),
        requests.exceptions.ConnectionError("down"),
    ],
)
def test_network_errors_propagate(monkeypatch, error):
    patch_get(monkeypatch, side_effect=error)
    with pytest.raises(type(error)):
        api_client.fetch_response("CVE-2099-10001")


def test_invalid_json_propagates(monkeypatch):
    response = make_response(200)
    response.json.side_effect = requests.exceptions.JSONDecodeError(
        "Invalid JSON", "{", 1
    )
    patch_get(monkeypatch, response)
    with pytest.raises(requests.exceptions.JSONDecodeError):
        api_client.fetch_response("CVE-2099-10001")


def test_real_requests_are_blocked():
    with pytest.raises(AttributeError):
        requests.get(URL, timeout=1)
