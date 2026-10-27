"""Завдання 1: модель користувача, сесії та аудиту (ООП)."""

from __future__ import annotations

import hashlib
import hmac
import os
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime

PBKDF2_ITERATIONS = 200_000
SESSION_TIMEOUT_SEC = 900
EMAIL_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_]{2,63}@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+$")


def _now() -> datetime:
    """Поточний час UTC з часовим поясом."""
    return datetime.now(UTC)


class User:
    """Користувач з безпечним зберіганням пароля та валідацією email."""

    def __init__(
        self, username: str, email: str, role: str = "user", active: bool = True
    ) -> None:
        self.username = username
        self.role = role
        self.active = active
        self._email = ""
        self.email = email  # проходить через setter із валідацією
        self.__password_hash = b""
        self.__password_salt = b""

    @property
    def email(self) -> str:
        """Електронна адреса користувача."""
        return self._email

    @email.setter
    def email(self, value: str) -> None:
        if not isinstance(value, str) or not EMAIL_RE.match(value):
            raise ValueError(f"Invalid email: {value!r}")
        self._email = value

    @staticmethod
    def _derive(password: str, salt: bytes) -> bytes:
        return hashlib.pbkdf2_hmac(
            "sha256", password.encode("utf-8"), salt, PBKDF2_ITERATIONS
        )

    def set_password(self, password: str) -> None:
        """Згенерувати нову сіль і зберегти хеш пароля."""
        self.__password_salt = os.urandom(16)
        self.__password_hash = self._derive(password, self.__password_salt)

    def check_password(self, password: str) -> bool:
        """Порівняти пароль зі збереженим хешем у сталому часі."""
        if not self.__password_hash:
            return False
        candidate = self._derive(password, self.__password_salt)
        return hmac.compare_digest(candidate, self.__password_hash)

    def deactivate(self) -> None:
        """Деактивувати обліковий запис."""
        self.active = False

    def __str__(self) -> str:
        state = "active" if self.active else "inactive"
        return f"User(username={self.username}, email={self.email}, role={self.role}, {state})"


class Admin(User):
    """Адміністратор із набором дозволів."""

    def __init__(self, username: str, email: str, active: bool = True) -> None:
        super().__init__(username, email, role="admin", active=active)
        self.permissions: set[str] = set()

    def grant_permission(self, permission: str) -> None:
        """Додати дозвіл."""
        self.permissions.add(permission)

    def revoke_permission(self, permission: str) -> None:
        """Прибрати дозвіл (якщо його немає — нічого не робить)."""
        self.permissions.discard(permission)

    def has_permission(self, permission: str) -> bool:
        """Перевірити наявність дозволу."""
        return permission in self.permissions

    def __str__(self) -> str:
        perms = ", ".join(sorted(self.permissions)) or "none"
        return f"{super().__str__()} permissions=[{perms}]"


class Session:
    """Сесія користувача з відстеженням активності."""

    def __init__(self, ip: str) -> None:
        self.ip = ip
        self.login_time = _now()
        self.last_activity = self.login_time

    def touch(self) -> None:
        """Оновити час останньої активності."""
        self.last_activity = _now()

    def is_active(self, timeout_sec: int) -> bool:
        """Сесія активна, якщо з останньої активності минуло менше timeout_sec."""
        if timeout_sec <= 0:
            raise ValueError("timeout_sec must be positive")
        return (_now() - self.last_activity).total_seconds() < timeout_sec


@dataclass
class AuditRecord:
    """Один запис журналу аудиту (без паролів)."""

    username: str
    action: str
    timestamp: datetime = field(default_factory=_now)


class AuditLog:
    """Журнал подій безпеки."""

    def __init__(self) -> None:
        self._records: list[AuditRecord] = []

    def add_log(self, username: str, action: str) -> None:
        """Додати подію: login_success, login_failure, logout."""
        self._records.append(AuditRecord(username, action))

    def show_all(self) -> None:
        """Вивести всі записи."""
        for rec in self._records:
            print(
                f"{rec.timestamp.isoformat(timespec='seconds')} | {rec.username:<8} | {rec.action}"
            )

    @property
    def records(self) -> list[AuditRecord]:
        """Копія записів журналу."""
        return list(self._records)


class UserAccount:
    """Композиція User + Session + AuditLog."""

    def __init__(
        self, user: User, session: Session | None = None, audit: AuditLog | None = None
    ) -> None:
        self.user = user
        self.session = session
        self.audit = audit if audit is not None else AuditLog()

    def login(self, username: str, password: str, ip: str) -> bool:
        """Вхід: перевірка активності, пароля, створення сесії, запис в аудит."""
        ok = (
            username == self.user.username
            and self.user.active
            and self.user.check_password(password)
        )
        if not ok:
            self.audit.add_log(username, "login_failure")
            return False
        self.session = Session(ip)
        self.session.touch()
        self.audit.add_log(username, "login_success")
        return True

    def is_authenticated(self) -> bool:
        """Є сесія і вона не прострочена (без продовження сесії)."""
        return self.session is not None and self.session.is_active(SESSION_TIMEOUT_SEC)

    def logout(self) -> None:
        """Завершити сесію та зафіксувати подію."""
        if self.session is not None:
            self.audit.add_log(self.user.username, "logout")
            self.session = None

    def __getitem__(self, key: str) -> object:
        if key == "user":
            return self.user
        if key == "session":
            return self.session
        if key == "audit":
            return self.audit
        raise KeyError(key)

    def __setitem__(self, key: str, value: object) -> None:
        expected: dict[str, type] = {
            "user": User,
            "session": Session,
            "audit": AuditLog,
        }
        if key not in expected:
            raise KeyError(key)
        if key == "session" and value is None:
            self.session = None
            return
        if not isinstance(value, expected[key]):
            raise TypeError(f"{key} must be {expected[key].__name__}")
        setattr(self, key, value)
