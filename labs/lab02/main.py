"""Точка входу ЛР №2: команди `demo` (Завдання 1) та `analyze` (Завдання 2)."""

from __future__ import annotations

import argparse
import logging
import sys
from datetime import timedelta

from labs.lab02 import task2
from labs.lab02.task1 import SESSION_TIMEOUT_SEC, Admin, AuditLog, User, UserAccount
from shared.student import VARIANT


def demo() -> int:
    """Демонстрація класів із Завдання 1."""
    audit = AuditLog()
    user = User("alice", "alice_01@example.com")
    user.set_password("S3cret!pass")
    account = UserAccount(user, audit=audit)

    print("--- Невдалий вхід ---")
    print("login (wrong password):", account.login("alice", "wrong", "10.0.0.5"))
    print("--- Успішний вхід ---")
    print("login (correct):", account.login("alice", "S3cret!pass", "10.0.0.5"))
    print("is_authenticated:", account.is_authenticated())

    print("--- Зміна email ---")
    user.email = "alice_new@example.org"
    print("new email:", user.email)
    try:
        user.email = "1bad@@example"
    except ValueError as exc:
        print("ValueError:", exc)

    print("--- Доступ через __getitem__ ---")
    print("account['user']:", account["user"])
    try:
        account["password"]
    except KeyError as exc:
        print("KeyError:", exc)
    try:
        account["user"] = "not a user"
    except TypeError as exc:
        print("TypeError:", exc)

    print("--- Права адміністратора ---")
    admin = Admin("root_admin", "root_admin@example.com")
    admin.grant_permission("read_logs")
    admin.grant_permission("manage_users")
    admin.revoke_permission("read_logs")
    print(admin)
    print("has manage_users:", admin.has_permission("manage_users"))

    print("--- Таймаут сесії ---")
    account.session.last_activity -= timedelta(seconds=SESSION_TIMEOUT_SEC + 1)
    print("is_authenticated after timeout:", account.is_authenticated())

    print("--- Вихід ---")
    account.login("alice", "S3cret!pass", "10.0.0.5")
    account.logout()
    print("is_authenticated after logout:", account.is_authenticated())

    print("--- Журнал аудиту ---")
    audit.show_all()
    return 0


def build_parser() -> argparse.ArgumentParser:
    """Побудувати CLI з підкомандами."""
    parser = argparse.ArgumentParser(
        prog="labs.lab02.main", description=f"ЛР №2 (варіант {VARIANT})"
    )
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("demo", help="демонстрація Завдання 1")
    p_analyze = sub.add_parser(
        "analyze", help="Завдання 2: монітор SSL/TLS сертифікатів"
    )
    task2.add_arguments(p_analyze)
    return parser


def main(argv: list[str] | None = None) -> int:
    """Розібрати аргументи та виконати команду."""
    logging.basicConfig(level=logging.INFO, format="[%(levelname)s] %(message)s")
    args = build_parser().parse_args(argv)
    if args.command == "demo":
        return demo()
    return task2.run(args)


if __name__ == "__main__":
    sys.exit(main())
