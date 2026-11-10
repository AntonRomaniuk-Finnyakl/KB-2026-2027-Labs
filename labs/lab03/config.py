
from typing import Literal, get_args

APP_TITLE = "Облік навантаження серверних ресурсів"
APP_DESCRIPTION = (
    "Сервіс обліку вимірювань використання серверних ресурсів "
    "Категорія визначає ресурс (cpu, memory, disk); "
    "value — використання ресурсу у відсотках (0–100); "
    "status — стан перевірки спостереження (new, in_progress, done). "
    "Поріг навантаження для аналізу: 80.0 %."
)
UNIT = "percent"
THRESHOLD = 80.0
VALUE_MIN = 0.0
VALUE_MAX = 100.0

Status = Literal["new", "in_progress", "done"]
STATUSES = get_args(Status)
