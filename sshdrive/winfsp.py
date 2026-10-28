"""Обнаружение и установка драйвера WinFsp.

WinFsp — единственная внешняя зависимость: это драйвер файловой системы
в пользовательском режиме, на нём rclone создаёт диск. Установка требует
прав администратора, поэтому запускается через UAC.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import tempfile
import urllib.request
from pathlib import Path
from typing import Callable

from . import paths, pwsh

Progress = Callable[[int, int], None]
Log = Callable[[str], None]

GITHUB_LATEST = "https://api.github.com/repos/winfsp/winfsp/releases/latest"
USER_AGENT = "SSHDrive/1.0"
RELEASE_PREFIX = "https://github.com/winfsp/winfsp/releases/download/"
# MSI должен быть подписан действительной подписью Authenticode И одним из этих
# издателей (подстрока в Subject сертификата, регистр не важен: в сертификате
# «CN=NAVIMATICS LLC»). Подпись «кого угодно» не годится. Значение сверено с
# реальным MSI; если WinFsp сменит сертификат, поправьте кортеж.
EXPECTED_SIGNERS = ("Navimatics LLC",)
EXIT_BAD_SIGNATURE = 10
EXIT_BAD_SIGNER = 11
EXIT_PREPARE_FAILED = 12
DEFAULT_PATHS = (
    Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")) / "WinFsp",
    Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "WinFsp",
)


def install_dir() -> Path | None:
    """Возвращает каталог установки WinFsp, если драйвер на месте."""
    candidates: list[Path] = list(DEFAULT_PATHS)

    try:
        import winreg

        for view in (winreg.KEY_WOW64_32KEY, winreg.KEY_WOW64_64KEY):
            for subkey in (r"SOFTWARE\WinFsp", r"SOFTWARE\WOW6432Node\WinFsp"):
                try:
                    with winreg.OpenKey(
                        winreg.HKEY_LOCAL_MACHINE,
                        subkey,
                        0,
                        winreg.KEY_READ | view,
                    ) as key:
                        value, _ = winreg.QueryValueEx(key, "InstallDir")
                        if value:
                            candidates.insert(0, Path(value))
                except OSError:
                    continue
    except ImportError:  # pragma: no cover
        pass

    for candidate in candidates:
        if (candidate / "bin" / "winfsp-x64.dll").is_file():
            return candidate
    return None


def is_installed() -> bool:
    return install_dir() is not None


def file_version(path: Path) -> str:
    """Версия exe/dll из ресурса версии (без запуска процесса)."""
    try:
        import ctypes
        from ctypes import wintypes

        version_dll = ctypes.WinDLL("version", use_last_error=True)
        version_dll.GetFileVersionInfoSizeW.argtypes = [
            wintypes.LPCWSTR,
            ctypes.POINTER(wintypes.DWORD),
        ]
        version_dll.GetFileVersionInfoSizeW.restype = wintypes.DWORD
        version_dll.GetFileVersionInfoW.argtypes = [
            wintypes.LPCWSTR,
            wintypes.DWORD,
            wintypes.DWORD,
            ctypes.c_void_p,
        ]
        version_dll.GetFileVersionInfoW.restype = wintypes.BOOL
        version_dll.VerQueryValueW.argtypes = [
            ctypes.c_void_p,
            wintypes.LPCWSTR,
            ctypes.POINTER(ctypes.c_void_p),
            ctypes.POINTER(wintypes.UINT),
        ]
        version_dll.VerQueryValueW.restype = wintypes.BOOL

        size = version_dll.GetFileVersionInfoSizeW(str(path), None)
        if not size:
            return ""
        buffer = ctypes.create_string_buffer(size)
        if not version_dll.GetFileVersionInfoW(str(path), 0, size, buffer):
            return ""
        pointer = ctypes.c_void_p()
        length = wintypes.UINT()
        if not version_dll.VerQueryValueW(buffer, "\\", ctypes.byref(pointer), ctypes.byref(length)):
            return ""
        fixed = ctypes.cast(pointer, ctypes.POINTER(wintypes.DWORD * 4)).contents
        ms, ls = fixed[2], fixed[3]
        return f"{ms >> 16}.{ms & 0xFFFF}.{ls >> 16}.{ls & 0xFFFF}"
    except Exception:
        return ""


def version() -> str:
    folder = install_dir()
    if folder is None:
        return ""
    return file_version(folder / "bin" / "winfsp-x64.dll")


def latest_msi() -> tuple[str, str]:
    """Возвращает (имя файла, URL) последнего MSI с GitHub."""
    request = urllib.request.Request(GITHUB_LATEST, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=30) as response:
        data = json.load(response)
    for asset in data.get("assets", []):
        name = asset.get("name", "")
        if name.lower().endswith(".msi"):
            url = asset["browser_download_url"]
            if not url.startswith(RELEASE_PREFIX):
                raise RuntimeError(f"Неожиданный адрес загрузки WinFsp: {url[:120]}")
            return os.path.basename(name), url
    raise RuntimeError("В последнем релизе WinFsp не найден MSI-файл")


_ps_quote = pwsh.quote
_ps_encoded = pwsh.encoded_args


def _signers_literal() -> str:
    return "@(" + ", ".join(_ps_quote(name) for name in EXPECTED_SIGNERS) + ")"


def download(progress: Progress | None = None, log: Log | None = None) -> Path:
    """Возвращает путь к MSI с проверенной подписью.

    Берётся MSI, встроенный в offline-сборку, иначе скачивается в новый
    приватный каталог. Каталог скачивания удаляет cleanup_download(): встроенные
    файлы и всё остальное он не трогает.
    """
    bundled = paths.bundled_glob("winfsp*.msi")
    if bundled:
        if log:
            log(f"Использую встроенный установщик {bundled[0].name}")
        _check_signature(bundled[0], log)
        return bundled[0]

    name, url = latest_msi()
    if not name.lower().endswith(".msi"):
        raise RuntimeError(f"Неожиданное имя установщика WinFsp: {name[:80]}")
    if log:
        log(f"Скачиваю {name}…")
    workdir = Path(tempfile.mkdtemp(prefix="sshdrive-winfsp-"))
    try:
        target = workdir / name
        request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
        with urllib.request.urlopen(request, timeout=120) as response, target.open("wb") as handle:
            total = int(response.headers.get("Content-Length") or 0)
            done = 0
            while True:
                chunk = response.read(256 * 1024)
                if not chunk:
                    break
                handle.write(chunk)
                done += len(chunk)
                if progress:
                    progress(done, total)
        _check_signature(target, log)
    except BaseException:
        shutil.rmtree(workdir, ignore_errors=True)
        raise
    return target


def cleanup_download(msi: Path) -> None:
    """Удаляет каталог, который создал download(); чужие каталоги не трогает."""
    parent = msi.parent
    try:
        ours = (
            parent.name.startswith("sshdrive-winfsp-")
            and parent.parent.resolve() == Path(tempfile.gettempdir()).resolve()
        )
    except OSError:
        return
    if ours:
        shutil.rmtree(parent, ignore_errors=True)


def _check_signature(msi: Path, log: Log | None) -> None:
    """Предварительная проверка подписи (быстрый отказ до запроса UAC).

    Если проверить не удалось — установка отменяется. Решающая проверка
    выполняется ещё раз в повышенном процессе, над защищённой копией файла.
    """
    script = f"""
$ErrorActionPreference = 'Stop'
$s = Get-AuthenticodeSignature -LiteralPath {_ps_quote(str(msi))}
if ($s.Status -ne 'Valid') {{ Write-Output ('BAD status ' + $s.Status); exit {EXIT_BAD_SIGNATURE} }}
$subject = $s.SignerCertificate.Subject
$match = $false
foreach ($n in {_signers_literal()}) {{ if ($subject.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) {{ $match = $true }} }}
if (-not $match) {{ Write-Output ('BAD signer ' + $subject); exit {EXIT_BAD_SIGNER} }}
Write-Output ('OK ' + $subject)
"""
    try:
        result = subprocess.run(
            [paths.powershell_exe(), *_ps_encoded(script)],
            capture_output=True,
            text=True,
            timeout=120,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except Exception as exc:  # noqa: BLE001
        raise RuntimeError(
            f"Не удалось проверить цифровую подпись установщика WinFsp ({type(exc).__name__}) — "
            "установка отменена."
        ) from exc
    text = (result.stdout or "").strip()
    if result.returncode != 0 or not text.startswith("OK"):
        raise RuntimeError(
            f"Подпись установщика WinFsp не прошла проверку: {text or (result.stderr or '').strip()[:200]}"
        )
    if log:
        log(f"Подпись MSI действительна: {text[3:].strip()[:120]}")


def install(progress: Progress | None = None, log: Log | None = None) -> None:
    """Скачивает и устанавливает WinFsp (появится запрос UAC)."""
    msi = download(progress, log)
    try:
        if log:
            log("Запускаю установщик (нужно подтвердить запрос UAC)…")
        # Повышенный процесс сам копирует MSI в %SystemRoot%\Temp (обычный
        # пользователь не может менять созданные там администратором файлы),
        # проверяет подпись копии и только потом запускает msiexec. Иначе
        # любая программа пользователя успела бы подменить MSI между проверкой
        # и установкой и получила бы права администратора.
        elevated = f"""
$ErrorActionPreference = 'Stop'
$code = {EXIT_PREPARE_FAILED}
$copy = Join-Path $env:SystemRoot ('Temp\\sshdrive-winfsp-' + [guid]::NewGuid().ToString('N') + '.msi')
try {{
    Copy-Item -LiteralPath {_ps_quote(str(msi))} -Destination $copy
    $s = Get-AuthenticodeSignature -LiteralPath $copy
    $match = $false
    if ($s.Status -eq 'Valid') {{
        foreach ($n in {_signers_literal()}) {{ if ($s.SignerCertificate.Subject.IndexOf($n, [StringComparison]::OrdinalIgnoreCase) -ge 0) {{ $match = $true }} }}
    }}
    if ($s.Status -ne 'Valid') {{ $code = {EXIT_BAD_SIGNATURE} }}
    elseif (-not $match) {{ $code = {EXIT_BAD_SIGNER} }}
    else {{
        $p = Start-Process -FilePath (Join-Path $env:SystemRoot 'System32\\msiexec.exe') -ArgumentList '/i', ('"' + $copy + '"'), '/qn', '/norestart' -Wait -PassThru
        $code = $p.ExitCode
    }}
}} catch {{
    $code = {EXIT_PREPARE_FAILED}
}} finally {{
    Remove-Item -LiteralPath $copy -Force -ErrorAction SilentlyContinue
}}
exit $code
"""
        encoded_args = ", ".join(_ps_quote(arg) for arg in _ps_encoded(elevated))
        launcher = (
            "$ErrorActionPreference='Stop'; "
            f"$p = Start-Process -FilePath {_ps_quote(paths.powershell_exe())} -Verb RunAs "
            f"-WindowStyle Hidden -Wait -PassThru -ArgumentList {encoded_args}; "
            "exit $p.ExitCode"
        )
        result = subprocess.run(
            [paths.powershell_exe(), *_ps_encoded(launcher)],
            capture_output=True,
            text=True,
            timeout=1800,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    finally:
        cleanup_download(msi)

    code = result.returncode
    if code == EXIT_BAD_SIGNATURE:
        raise RuntimeError("Подпись установщика WinFsp недействительна — установка отменена.")
    if code == EXIT_BAD_SIGNER:
        raise RuntimeError("Установщик WinFsp подписан неожиданным издателем — установка отменена.")
    if code == EXIT_PREPARE_FAILED:
        raise RuntimeError("Не удалось подготовить установщик WinFsp (запрос UAC отклонён?).")
    if code not in (0, 3010):
        raise RuntimeError(
            f"Установщик WinFsp завершился с кодом {code}. "
            f"{(result.stderr or '').strip()[:300]}"
        )
    if not is_installed():
        raise RuntimeError("WinFsp установлен, но DLL не найдена. Возможно, нужна перезагрузка.")
    if log:
        log("WinFsp установлен.")
