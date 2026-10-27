import csv
import functools
import hashlib
import json
import os
import sys
from datetime import UTC, datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
CSV_PATH = os.path.join(DATA_DIR, "users.csv")
LOG_PATH = os.path.join(DATA_DIR, "log.json")

MIN_PASSWORD_LENGTH = 10


class ValidationError(Exception):
    pass


def get_salt() -> str:
    return str(VARIANT).zfill(5)


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль та сіль не можуть бути порожніми.")

    if len(password) < MIN_PASSWORD_LENGTH:
        raise ValidationError(f"Пароль занадто короткий (менше {MIN_PASSWORD_LENGTH}).")

    full_string = password + salt
    encoded_bytes = full_string.encode("utf-8")

    hasher = hashlib.sha3_384()
    hasher.update(encoded_bytes)
    return hasher.hexdigest()


def log_event(func):
    @functools.wraps(func)
    def wrapper(username: str, password: str):
        result = "failure"
        try:
            is_success = func(username, password)
            if is_success:
                result = "success"
            return is_success
        finally:
            os.makedirs(DATA_DIR, exist_ok=True)
            log_record = {
                "event": "login",
                "user": username,
                "result": result,
                "timestamp": datetime.now(UTC).strftime("%Y-%m-%d %H:%M:%S UTC"),
                "args": [username, password],
                "kwargs": {},
            }

            history = []
            if os.path.exists(LOG_PATH):
                try:
                    with open(LOG_PATH, mode="r", encoding="utf-8") as file:
                        history = json.load(file)
                except (OSError, json.JSONDecodeError):
                    history = []

            history.append(log_record)
            with open(LOG_PATH, mode="w", encoding="utf-8") as file:
                json.dump(history, file, indent=4, ensure_ascii=False)

    return wrapper


def create_user(username: str, password: str) -> tuple[str, str]:
    salt = get_salt()
    pwd_hash = generate_hash(password, salt)
    return username, pwd_hash


def create_users(users_list: tuple[tuple[str, str], ...]) -> None:
    os.makedirs(DATA_DIR, exist_ok=True)
    with open(CSV_PATH, mode="w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["username", "password_hash"])
        for username, password in users_list:
            row = create_user(username, password)
            writer.writerow(row)


def read_users_db() -> list[dict[str, str]]:
    if not os.path.exists(CSV_PATH):
        raise FileNotFoundError(f"Файл {CSV_PATH} не знайдено.")

    with open(CSV_PATH, mode="r", encoding="utf-8") as file:
        reader = csv.DictReader(file)
        return list(reader)


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін і пароль обов'язкові.")

    salt = get_salt()
    entered_hash = generate_hash(password, salt)
    users = read_users_db()

    for user in users:
        if user["username"] == username and user["password_hash"] == entered_hash:
            return True

    return False


def run_task3() -> None:
    print("=" * 60)
    print(f"ЗАВДАННЯ 3 | {STUDENT_NAME}, Варіант: {VARIANT}")
    print("=" * 60)

    sample_users = (
        ("sec_alice", "AliceSecurePass1!"),
        ("sec_bob", "BobSecretP@ssword2"),
        ("sec_charlie", "CharlieSafe#2024"),
        ("sec_david", "DavidDefend$44"),
        ("sec_eve", "EveEavesdrop%55"),
        ("sec_frank", "FrankFirew@ll66"),
        ("sec_grace", "GraceGu@rd77!"),
        ("sec_heidi", "HeidiH@ckProof8"),
        ("sec_ivan", "IvanIntrus10n99"),
        ("sec_judy", "JudyJustice!!00"),
    )

    try:
        print("[1] Запис користувачів у файл CSV...")
        create_users(sample_users)
        print(f"Збережено у {CSV_PATH}")

        print("\n[2] Зчитування з CSV бази:")
        data = read_users_db()
        for user in data:
            print(
                f"Користувач: {user['username']:<12} | Хеш: {user['password_hash'][:25]}..."
            )

        print("\n[3] Тестування входу:")
        res_ok = login("sec_alice", "AliceSecurePass1!")
        print(f"Вхід sec_alice з правильним паролем: {res_ok}")

        res_bad = login("sec_alice", "WrongPass123")
        print(f"Вхід sec_alice з неправильним паролем: {res_bad}")

        try:
            login("sec_bob", "123")
        except ValidationError as err:
            print(f"Очікувана помилка валідації пароля: {err}")

        print(f"\nСпроби записані в {LOG_PATH}")

    except OSError as err:
        print(f"Помилка файлів: {err}")


if __name__ == "__main__":
    run_task3()
