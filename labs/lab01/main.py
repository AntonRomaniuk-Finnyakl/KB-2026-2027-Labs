import os
import sys

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))

from labs.lab01.task1 import run_task1
from labs.lab01.task2 import run_task2
from labs.lab01.task3 import run_task3
from shared.student import GROUP, STUDENT_NAME, VARIANT


def main() -> None:
    print("=" * 60)
    print("ЛАБОРАТОРНА РОБОТА №1")
    print(f"Студент: {STUDENT_NAME}")
    print(f"Група:   {GROUP}")
    print(f"Варіант: {VARIANT}")
    print("=" * 60)
    print("\n")

    run_task1()
    print("\n\n")

    run_task2()
    print("\n\n")

    run_task3()
    print("\n\nВсі завдання  виконані.")


if __name__ == "__main__":
    main()
