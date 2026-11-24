"""Клієнт NVD CVE API 2.0: один GET-запит без повторів і перенаправлень."""

import os
from typing import Any

import requests

API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
TIMEOUT = (3.05, 10)


class UnexpectedStatusError(Exception):
    """Сервер повернув успішний за формою, але не очікуваний статус (не 200)."""

    def __init__(self, status_code: int) -> None:
        super().__init__(f"Неочікуваний HTTP-статус {status_code}")
        self.status_code = status_code


def build_headers() -> dict[str, str]:
    """Повернути заголовки запиту; apiKey додається, лише якщо ключ задано."""
    headers = {"Accept": "application/json"}
    api_key = os.getenv("NVD_API_KEY")
    if api_key is not None and api_key.strip():
        headers["apiKey"] = api_key.strip()
    return headers


def fetch_response(cve_id: str) -> Any:
    """Виконати один GET-запит до NVD і повернути декодований JSON.

    Винятки Requests (мережеві, HTTP, JSON) не перехоплюються: їх обробляє main.
    """
    response = requests.get(
        API_URL,
        params={"cveId": cve_id},
        headers=build_headers(),
        timeout=TIMEOUT,
        allow_redirects=False,
    )
    response.raise_for_status()
    if response.status_code != 200:
        raise UnexpectedStatusError(response.status_code)
    return response.json()
