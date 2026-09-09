import os
import random
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT

PASSWORDS = [
    "Social@Engineer",
    "basic",
    "Phishing@D3tect",
    "client",
    "Ransomwar3@Protect",
    "general",
    "Zero@D4y",
    "generic",
    "Bug@Bounty",
    "standard123",
]

CRITERIA = {
    "min_length": 11,
    "require_digits": True,
    "require_upper": True,
    "require_special": True,
}

FORBIDDEN_PASSWORDS = {
    "basic",
    "client",
    "general",
    "generic",
    "standard123",
    "guest",
}

SPECIAL_SYMBOLS = "!@#$%^&*()-_=+[{]}\\|;:'\",<.>/?`~"


def evaluate_password(pwd: str, all_passwords: list[str]) -> str:
    min_len = CRITERIA["min_length"]

    if pwd in FORBIDDEN_PASSWORDS or len(pwd) < min_len:
        return "Заборонений"

    has_digit = False
    has_upper = False
    has_lower = False
    has_special = False

    for char in pwd:
        if char.isdigit():
            has_digit = True
        elif char.isupper():
            has_upper = True
        elif char.islower():
            has_lower = True
        elif char in SPECIAL_SYMBOLS:
            has_special = True

    all_criteria_met = has_digit and has_upper and has_special
    repeats_count = all_passwords.count(pwd)

    if all_criteria_met and len(pwd) >= min_len + 4 and repeats_count == 1:
        return "Дуже сильний"

    if all_criteria_met:
        return "Сильний"

    has_any = has_digit or has_upper or has_lower or has_special
    if has_any:
        return "Середній"

    return "Слабкий"


def run_task1() -> None:
    print("=" * 60)
    print(f"ЗАВДАННЯ 1 | {STUDENT_NAME}, Варіант: {VARIANT}")
    print("=" * 60)

    passwords_copy = list(PASSWORDS)

    random.seed(VARIANT)
    for _ in range(3):
        random_index = random.randint(0, len(passwords_copy) - 1)
        duplicate_pwd = passwords_copy[random_index]
        passwords_copy.append(duplicate_pwd)

    print(f"{'Пароль':<22} | {'Довжина':<8} | {'Повторів':<8} | {'Оцінка'}")
    print("-" * 60)

    for pwd in passwords_copy:
        grade = evaluate_password(pwd, passwords_copy)
        count = passwords_copy.count(pwd)
        print(f"{pwd:<22} | {len(pwd):<8} | {count:<8} | {grade}")


if __name__ == "__main__":
    run_task1()
