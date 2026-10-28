"""Скачивает WiX Toolset 3.14 (portable binaries) в build/wix.

Нужен только для сборки MSI; интернет требуется один раз.
"""

from __future__ import annotations

import hashlib
import io
import shutil
import sys
import urllib.request
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TARGET = ROOT / "build" / "wix"
URL = (
    "https://github.com/wixtoolset/wix3/releases/download/"
    "wix3141rtm/wix314-binaries.zip"
)
# SHA256 архива, снятый при закреплении версии (GitHub его для WiX не публикует).
# Меняете URL — обновите и хэш.
SHA256 = "6ac824e1642d6f7277d0ed7ea09411a508f6116ba6fae0aa5f2c7daa2ff43d31"
# Отметка «этот каталог распакован из архива с таким хэшем». Без неё уже лежащий
# build/wix (например, от версии скрипта без проверки) на веру не принимается.
MARKER = ".verified-sha256"


def main() -> int:
    marker = TARGET / MARKER
    ready = (TARGET / "candle.exe").is_file() and (TARGET / "light.exe").is_file()
    if ready and marker.is_file() and marker.read_text(encoding="ascii").strip() == SHA256:
        print(f"WiX уже распакован и проверен: {TARGET}")
        return 0
    if TARGET.exists():
        print(f"{TARGET} не проверен или устарел — скачиваю заново")
        shutil.rmtree(TARGET)

    print("Скачиваю WiX Toolset 3.14…")
    request = urllib.request.Request(URL, headers={"User-Agent": "SSHDrive-build"})
    with urllib.request.urlopen(request, timeout=180) as response:
        data = response.read()

    actual = hashlib.sha256(data).hexdigest()
    if actual != SHA256:
        print(
            "Контрольная сумма WiX не совпала — архив повреждён или подменён.\n"
            f"  ожидалась {SHA256}\n  получена  {actual}",
            file=sys.stderr,
        )
        return 1

    TARGET.mkdir(parents=True, exist_ok=True)
    # Распаковываем те же байты, что проверили (без промежуточного файла).
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        zf.extractall(TARGET)

    if not (TARGET / "light.exe").is_file():
        print("в архиве WiX не найден light.exe", file=sys.stderr)
        return 1
    marker.write_text(SHA256 + "\n", encoding="ascii")
    print(f"WiX готов: {TARGET}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
