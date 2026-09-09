import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import STUDENT_NAME, VARIANT

USERS = {
    "iot_specialist": {
        "role": "iot_security",
        "clearance": 3,
        "department": "IoT",
        "active": True,
    },
    "mobile_analyst": {
        "role": "mobile_security",
        "clearance": 3,
        "department": "Mobile",
        "active": True,
    },
    "web_developer": {
        "role": "web_developer",
        "clearance": 2,
        "department": "Web",
        "active": True,
    },
    "api_consumer": {
        "role": "api_user",
        "clearance": 2,
        "department": "Integration",
        "active": True,
    },
    "demo_account": {
        "role": "demonstration",
        "clearance": 1,
        "department": "Demo",
        "active": False,
    },
}

RESOURCES = [
    ("iot_firmware", 3),
    ("mobile_policies", 3),
    ("web_applications", 2),
    ("api_gateway", 2),
    ("device_certificates", 3),
    ("app_store", 1),
    ("vulnerability_database", 3),
    ("device_management", 3),
    ("integration_docs", 2),
    ("demo_content", 1),
]

SECURITY_LEVELS = ("Consumer", "Business", "Enterprise", "Critical Systems")

BLOCKED_USERS = {"demo_account", "compromised_device", "malicious_app"}


def check_access(user_login: str, resource_level: int) -> tuple[str, str]:
    if user_login not in USERS:
        return "DENY", "User not found"

    if user_login in BLOCKED_USERS:
        return "DENY", "User is blocked"

    user_info = USERS[user_login]
    if user_info["active"] is False:
        return "DENY", "Account inactive"

    if user_info["clearance"] >= resource_level:
        return "ALLOW", ""

    return "DENY", "Insufficient clearance"


def run_task2() -> None:
    print("=" * 60)
    print(f"ЗАВДАННЯ 2 | {STUDENT_NAME}, Варіант: {VARIANT}")
    print("=" * 60)

    print("СПИСОК РЕСУРСІВ:")
    for resource_name, level_number in RESOURCES:
        level_title = SECURITY_LEVELS[level_number - 1]
        print(f" - {resource_name:<24} [Рівень: {level_title}]")
    print("-" * 60)

    print("РЕЗУЛЬТАТ ПЕРЕВІРКИ ДОСТУПУ:")
    for user_login in USERS:
        for resource_name, level_number in RESOURCES:
            status, reason = check_access(user_login, level_number)
            if status == "ALLOW":
                print(f"user={user_login:<16} resource={resource_name:<24} -> ALLOW")
            else:
                print(
                    f"user={user_login:<16} resource={resource_name:<24} -> DENY ({reason})"
                )


if __name__ == "__main__":
    run_task2()
