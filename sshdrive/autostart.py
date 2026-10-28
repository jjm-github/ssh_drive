"""Автозапуск при входе в Windows.

Используется ярлык в папке «Автозагрузка» текущего пользователя — его видно
в `shell:startup`, он не требует прав администратора и удаляется вместе с MSI.
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from . import paths, pwsh

SHORTCUT_NAME = "SSH Drive.lnk"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def startup_dir() -> Path:
    base = os.environ.get("APPDATA")
    root = Path(base) if base else Path.home() / "AppData" / "Roaming"
    return root / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"


def shortcut_path() -> Path:
    return startup_dir() / SHORTCUT_NAME


def is_enabled() -> bool:
    return shortcut_path().is_file()


def _target() -> tuple[Path, str, Path]:
    """Возвращает (exe, аргументы, рабочая папка) для автозапуска."""
    if getattr(sys, "frozen", False):
        exe = Path(sys.executable).resolve()
        return exe, "--tray", exe.parent
    python = Path(sys.executable).resolve()
    pythonw = python.with_name("pythonw.exe")
    exe = pythonw if pythonw.is_file() else python
    workdir = Path(__file__).resolve().parent.parent
    return exe, "-m sshdrive --tray", workdir


def enable() -> None:
    exe, args, workdir = _target()
    link = shortcut_path()
    link.parent.mkdir(parents=True, exist_ok=True)
    script = (
        "$ws = New-Object -ComObject WScript.Shell; "
        f"$sc = $ws.CreateShortcut({pwsh.quote(link)}); "
        f"$sc.TargetPath = {pwsh.quote(exe)}; "
        f"$sc.Arguments = {pwsh.quote(args)}; "
        f"$sc.WorkingDirectory = {pwsh.quote(workdir)}; "
        f"$sc.IconLocation = {pwsh.quote(f'{exe},0')}; "
        "$sc.Description = 'SSH Drive'; "
        "$sc.Save()"
    )
    result = subprocess.run(
        [paths.powershell_exe(), *pwsh.encoded_args(script)],
        capture_output=True,
        text=True,
        timeout=60,
        creationflags=CREATE_NO_WINDOW,
    )
    if result.returncode != 0 or not link.is_file():
        raise RuntimeError((result.stderr or result.stdout or "не удалось создать ярлык").strip())


def disable() -> None:
    try:
        shortcut_path().unlink(missing_ok=True)
    except OSError as exc:
        raise RuntimeError(str(exc)) from exc


def describe() -> str:
    """Короткое описание для журнала."""
    if not is_enabled():
        return "выключен"
    return str(shortcut_path())
