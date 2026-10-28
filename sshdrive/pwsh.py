"""Безопасная сборка команд для PowerShell."""

from __future__ import annotations

import base64
import re

# PowerShell считает одинарными кавычками и типографские (U+2018..U+201B):
# имя пользователя вроде «O’Brien» иначе выводит текст за пределы строки.
_QUOTES = re.compile("(['‘’‚‛])")


def quote(value: object) -> str:
    """Строка для PowerShell в одинарных кавычках."""
    return "'" + _QUOTES.sub(r"\1\1", str(value)) + "'"


def encoded_args(script: str) -> list[str]:
    """Аргументы powershell.exe для запуска скрипта без разбора кавычек."""
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return ["-NoProfile", "-NonInteractive", "-EncodedCommand", encoded]
