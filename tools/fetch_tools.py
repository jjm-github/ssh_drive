"""Скачивает rclone.exe и установщик WinFsp в build/ для offline-сборки exe.

Запускается из build_exe.bat. Нужен интернет только на этапе сборки.
"""

from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from sshdrive import paths, rclone, winfsp  # noqa: E402

BUILD = ROOT / "build"


def main() -> int:
    BUILD.mkdir(parents=True, exist_ok=True)

    # переадресуем «установку» rclone в build/
    paths.bin_dir = lambda: BUILD  # type: ignore[assignment]
    paths.rclone_exe = lambda: BUILD / "rclone.exe"  # type: ignore[assignment]

    exe = BUILD / "rclone.exe"
    if exe.is_file() and not rclone.is_pinned_exe(exe):
        print(f"{exe} не совпадает с закреплённой версией — скачиваю заново")
        exe.unlink()
    if exe.is_file():
        print(f"rclone уже есть: {exe}")
    else:
        rclone.download_executable(log=lambda message: print("rclone:", message))
    if not exe.is_file():
        print("не удалось получить rclone.exe", file=sys.stderr)
        return 1
    print(f"rclone: {exe} ({exe.stat().st_size // (1024 * 1024)} МБ)")

    msi = winfsp.download(log=lambda message: print("winfsp:", message))
    versioned = BUILD / msi.name
    if msi.resolve() != versioned.resolve():
        shutil.copy2(msi, versioned)
    plain = BUILD / "winfsp.msi"
    if msi.resolve() != plain.resolve():
        shutil.copy2(msi, plain)
    winfsp.cleanup_download(msi)
    print(f"WinFsp MSI: {versioned} ({versioned.stat().st_size // 1024} КБ)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
