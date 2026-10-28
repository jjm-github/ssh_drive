"""Управление rclone: скачивание, монтирование SFTP как диска, размонтирование."""

from __future__ import annotations

import ctypes
import hashlib
import io
import os
import re
import shlex
import shutil
import subprocess
import tempfile
import threading
import time
import urllib.request
import zipfile
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Callable

from . import keys, paths
from .profiles import Profile

Progress = Callable[[int, int], None]
Log = Callable[[str], None]
LineHandler = Callable[[str], None]

USER_AGENT = "SSHDrive/1.0"
# Версия и SHA256 архива зашиты в код: хэш из того же релиза, что и сам архив,
# от подмены релиза не защищает. Чтобы обновить rclone, поменяйте обе константы
# (хэш — из SHA256SUMS нужного релиза, лучше после проверки его PGP-подписи).
PINNED_VERSION = "v1.75.2"
PINNED_SHA256 = "8a9db2bad1dc79a65b3348fd857069598e2aab7cf4d118b77b1df23055aff818"
# SHA256 самого rclone.exe из этого архива. Нужен, чтобы доверять rclone.exe,
# лежащему рядом с программой: в «Загрузках» там мог оказаться любой файл.
PINNED_EXE_SHA256 = "41eab3e118d264920b62c3327966c5ece0dc4dd715ee617d9e30450d8ead95a4"
CREATE_NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


# При монтировании WinFsp спрашивает у rclone, не символическая ли ссылка корень
# диска «/» (readlink). Без --links rclone отвечает ENOSYS («ссылок нет»), драйвер
# идёт дальше, но сам rclone при этом пишет ERROR. Это безвредно и бывает на каждом
# подключении, поэтому такую строку (и только для корня) не показываем. Для других
# путей сообщение значит реальное чтение ссылки и остаётся в журнале.
_BENIGN_LINES = (
    re.compile(r"\bsymlinks not supported without the --links flag: /\s*$"),
)


def is_benign_line(line: str) -> bool:
    """Строка вывода rclone, которую не нужно показывать пользователю."""
    return any(pattern.search(line) for pattern in _BENIGN_LINES)


class RcloneError(RuntimeError):
    """rclone недоступен или не смог смонтировать диск."""


# --------------------------------------------------------------------------
# Поиск и установка rclone.exe
# --------------------------------------------------------------------------
def find_exe() -> str | None:
    override = os.environ.get("SSHDRIVE_RCLONE")
    if override and Path(override).is_file():
        return str(Path(override))
    # rclone рядом с exe (MSI, портативная папка): берём только тот, что
    # байт в байт совпадает с закреплённой версией. Иначе любой rclone.exe,
    # скачанный в ту же папку, получил бы пароли раньше нашего.
    beside_exe = paths.install_dir() / "rclone.exe"
    if is_pinned_exe(beside_exe):
        return str(beside_exe)
    local = paths.rclone_exe()
    if local.is_file():
        return str(local)
    # rclone, встроенный в offline-сборку exe (его SHA256 сверен при сборке)
    bundled = paths.bundled_file("rclone.exe")
    if bundled is not None and is_pinned_exe(bundled):
        return str(bundled)
    return _which_safe()


@lru_cache(maxsize=8)
def _sha256_of(path: str, mtime_ns: int, size: int) -> str:  # noqa: ARG001 - ключ кэша
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def is_pinned_exe(path: str | Path) -> bool:
    """Файл существует и совпадает с rclone.exe закреплённой версии."""
    path = Path(path)
    try:
        info = path.stat()
        return _sha256_of(str(path), info.st_mtime_ns, info.st_size) == PINNED_EXE_SHA256
    except OSError:
        return False


def _which_safe() -> str | None:
    """Ищет rclone в PATH, но не в текущем каталоге и не по относительным путям.

    shutil.which на Windows неявно смотрит в текущий каталог (им может быть
    папка проекта), а rclone получает пароль и ключ.
    """
    name = "rclone.exe" if os.name == "nt" else "rclone"
    try:
        cwd = Path.cwd().resolve()
    except OSError:
        cwd = None
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        entry = entry.strip().strip('"')
        if not entry or not os.path.isabs(entry):
            continue
        folder = Path(entry)
        try:
            if cwd is not None and folder.resolve() == cwd:
                continue
        except OSError:
            continue
        candidate = folder / name
        if candidate.is_file():
            return str(candidate)
    return None


def version(exe: str | None = None) -> str:
    exe = exe or find_exe()
    if not exe:
        return ""
    try:
        result = subprocess.run(
            [exe, "version"],
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
        first = (result.stdout or "").strip().splitlines()
        if first and first[0].lower().startswith("rclone v"):
            return first[0].split()[1]
    except Exception:
        pass
    return ""


@lru_cache(maxsize=8)
def supports_host_key_pinning(exe: str) -> bool:
    """Пиннинг ключа хоста (host_keys) появился в rclone 1.75."""
    raw = version(exe).lstrip("vV")
    try:
        major, minor = (int(part) for part in raw.split(".")[:2])
    except (TypeError, ValueError):
        return False
    return (major, minor) >= (1, 75)


def _release() -> tuple[str, str, str]:
    """Возвращает (версия, url zip, ожидаемый SHA256) закреплённого релиза."""
    url = (
        f"https://github.com/rclone/rclone/releases/download/{PINNED_VERSION}/"
        f"rclone-{PINNED_VERSION}-windows-amd64.zip"
    )
    return PINNED_VERSION, url, PINNED_SHA256


def _fetch(url: str, dest: Path, progress: Progress | None = None) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=120) as response, dest.open("wb") as handle:
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


def download_executable(progress: Progress | None = None, log: Log | None = None) -> str:
    """Скачивает rclone с GitHub, сверяет SHA256 и кладёт в %LOCALAPPDATA%.

    Без совпадения хэша ничего не устанавливается.
    """
    tag, url, expected = _release()
    archive_name = url.rsplit("/", 1)[-1]
    workdir = Path(tempfile.mkdtemp(prefix="sshdrive-"))
    try:
        archive = workdir / archive_name
        if log:
            log(f"Скачиваю rclone {tag} ({archive_name})…")
        _fetch(url, archive, progress)

        # Читаем архив один раз: проверяем и распаковываем одни и те же байты.
        blob = archive.read_bytes()
        if hashlib.sha256(blob).hexdigest() != expected.lower():
            raise RcloneError(
                "Контрольная сумма rclone не совпала — скачивание повреждено или подменено. "
                "Установка отменена."
            )
        if log:
            log("SHA256 совпала.")

        with zipfile.ZipFile(io.BytesIO(blob)) as zf:
            member = next(
                (n for n in zf.namelist() if n.lower().rsplit("/", 1)[-1] == "rclone.exe"), None
            )
            if member is None:
                raise RcloneError("В архиве rclone не найден rclone.exe")
            data = zf.read(member)
        if hashlib.sha256(data).hexdigest() != PINNED_EXE_SHA256:
            raise RcloneError("rclone.exe в архиве не совпал с закреплённым — установка отменена.")

        paths.bin_dir().mkdir(parents=True, exist_ok=True)
        target = paths.rclone_exe()
        tmp = target.with_suffix(".exe.tmp")
        tmp.write_bytes(data)
        try:
            os.replace(tmp, target)
        except OSError as exc:
            raise RcloneError(
                f"Не удалось записать {target}: {exc}. Закройте уже запущенный rclone и повторите."
            ) from exc
    finally:
        shutil.rmtree(workdir, ignore_errors=True)
    if log:
        log(f"rclone установлен: {target}")
    return str(target)


def ensure_executable(progress: Progress | None = None, log: Log | None = None) -> str:
    exe = find_exe()
    if exe:
        return exe
    return download_executable(progress, log)


def obscure(exe: str, secret: str) -> str:
    """Кодирует пароль так, как его ждёт rclone (это не шифрование!).

    Пароль передаётся через stdin: аргументы процесса видны другим программам,
    попадают в аудит командных строк и в текст исключений.
    """
    if "\n" in secret or "\r" in secret:
        raise RcloneError("Пароль не должен содержать переводов строк")
    try:
        result = subprocess.run(
            [exe, "obscure", "-"],
            input=secret + "\n",
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=CREATE_NO_WINDOW,
        )
    except subprocess.TimeoutExpired as exc:
        raise RcloneError("rclone obscure не ответил за 30 с") from exc
    except OSError as exc:
        raise RcloneError(f"Не удалось запустить rclone obscure: {exc.strerror or exc}") from exc
    value = (result.stdout or "").strip()
    if result.returncode != 0 or not value:
        raise RcloneError(f"rclone obscure завершился с ошибкой: {(result.stderr or '').strip()[:200]}")
    return value


# --------------------------------------------------------------------------
# Буквы дисков
# --------------------------------------------------------------------------
def used_drives() -> set[str]:
    try:
        mask = ctypes.windll.kernel32.GetLogicalDrives()
        return {chr(ord("A") + i) for i in range(26) if mask & (1 << i)}
    except Exception:
        return {d for d in "ABCDEFGHIJKLMNOPQRSTUVWXYZ" if os.path.exists(f"{d}:\\")}


def free_letters() -> list[str]:
    used = used_drives()
    preferred = list("ZYXWVUTSRQPONMLKJ")
    return [letter for letter in preferred if letter not in used]


def drive_exists(letter: str) -> bool:
    return letter.upper() in used_drives()


# --------------------------------------------------------------------------
# Монтирование
# --------------------------------------------------------------------------
@dataclass
class MountHandle:
    profile_id: str
    drive: str
    proc: subprocess.Popen
    output: list[str] = field(default_factory=list)

    @property
    def alive(self) -> bool:
        return self.proc.poll() is None

    def stop(self, timeout: float = 12.0) -> None:
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                self.proc.kill()
                try:
                    self.proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    pass

        # WinFsp иногда не успевает убрать букву — пробуем освободить её.
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline and drive_exists(self.drive):
            time.sleep(0.25)
        if drive_exists(self.drive):
            try:
                subprocess.run(
                    [paths.system_exe("net.exe"), "use", f"{self.drive}:", "/delete", "/y"],
                    capture_output=True,
                    timeout=15,
                    creationflags=CREATE_NO_WINDOW,
                )
            except Exception:
                pass


def _split_extra(extra: str) -> list[str]:
    if not extra.strip():
        return []
    try:
        parts = shlex.split(extra, posix=False)
    except ValueError:
        parts = extra.split()
    cleaned = []
    for part in parts:
        if len(part) >= 2 and part[0] == part[-1] and part[0] in "\"'":
            part = part[1:-1]
        cleaned.append(part)
    return cleaned


# «Доп. опции rclone» — белый список. Произвольные флаги дают выполнение кода:
# --sftp-ssh запускает любую команду, --rc* открывает управляющий сервер,
# --sftp-pass / --sftp-key-file / --config подменяют учётные данные и т. д.
ALLOWED_EXTRA_FLAGS = frozenset(
    {
        "transfers", "checkers", "buffer-size", "dir-cache-time", "attr-timeout",
        "poll-interval", "read-only", "umask", "no-modtime", "no-checksum", "no-seek",
        "timeout", "contimeout", "retries", "low-level-retries", "bwlimit", "bwlimit-file",
        "write-back-cache", "direct-io",
        "sftp-concurrency", "sftp-chunk-size", "sftp-disable-hashcheck",
        "sftp-idle-timeout", "sftp-set-modtime", "sftp-use-fstat",
        "sftp-disable-concurrent-reads", "sftp-disable-concurrent-writes",
    }
)
ALLOWED_EXTRA_PREFIXES = ("vfs-",)


def validate_extra(extra: str) -> list[str]:
    """Разбирает «Доп. опции rclone» и пропускает только разрешённые флаги."""
    parts = _split_extra(extra)
    rejected = []
    for part in parts:
        if not part.startswith("-"):
            continue  # значение предыдущего флага
        name = part.lstrip("-").split("=", 1)[0].lower()
        if part.startswith("---") or not (
            name in ALLOWED_EXTRA_FLAGS or name.startswith(ALLOWED_EXTRA_PREFIXES)
        ):
            rejected.append(part)
    if rejected:
        raise RcloneError(
            "Эти опции rclone не разрешены: " + ", ".join(rejected)
            + ".\nМожно: --vfs-*, " + ", ".join(f"--{n}" for n in sorted(ALLOWED_EXTRA_FLAGS))
        )
    return parts


def mount(
    profile: Profile,
    *,
    password: str = "",
    passphrase: str = "",
    drive: str,
    host_key: str = "",
    on_line: LineHandler | None = None,
    timeout: float = 45.0,
) -> MountHandle:
    """Запускает `rclone mount` и ждёт появления диска.

    host_key — строка вида «ssh-ed25519 AAAA…», проверенная paramiko.
    rclone пинится на неё: и алгоритм согласования, и байты ключа.
    """
    exe = find_exe()
    if not exe:
        raise RcloneError("rclone.exe не найден. Меню «Сервис → Скачать rclone».")
    if drive_exists(drive):
        raise RcloneError(f"Диск {drive}: уже занят")
    extra_args = validate_extra(profile.extra_opts)

    env = {k: v for k, v in os.environ.items() if not k.startswith("RCLONE_")}
    env["RCLONE_CONFIG_SSHDRIVE_TYPE"] = "sftp"
    env["RCLONE_CONFIG_SSHDRIVE_HOST"] = profile.host
    env["RCLONE_CONFIG_SSHDRIVE_USER"] = profile.user
    env["RCLONE_CONFIG_SSHDRIVE_PORT"] = str(profile.port)
    env["RCLONE_CONFIG_SSHDRIVE_KEY_USE_AGENT"] = "false"

    if profile.auth == "key":
        key_path = Path(profile.key_path)
        if passphrase:
            # rclone не читает зашифрованные ключи нового формата. Расшифрованный
            # PEM отдаём через окружение процесса (key_pem, переводы строк как \n),
            # на диск он не попадает.
            pem = keys.export_unencrypted_pem(key_path, passphrase)
            env["RCLONE_CONFIG_SSHDRIVE_KEY_PEM"] = pem.strip().replace("\r\n", "\n").replace(
                "\n", "\\n"
            )
        else:
            env["RCLONE_CONFIG_SSHDRIVE_KEY_FILE"] = paths.forward_slashes(key_path)
    elif profile.auth == "agent":
        if not profile.agent_key:
            raise RcloneError("В профиле не выбран ключ из SSH-агента")
        # rclone ищет агента сам (Pageant, затем OpenSSH-агент — как и paramiko).
        # Если задан key_file, он читает «<key_file>.pub» и запрашивает у агента
        # только этот ключ. Приватного файла нет: key_file — лишь «имя» для .pub.
        agent_dir = paths.agent_dir()
        agent_dir.mkdir(parents=True, exist_ok=True)
        pub_file = agent_dir / f"{profile.id}.pub"
        pub_file.write_text(profile.agent_key + "\n", encoding="ascii")
        env["RCLONE_CONFIG_SSHDRIVE_KEY_USE_AGENT"] = "true"
        env["RCLONE_CONFIG_SSHDRIVE_KEY_FILE"] = paths.forward_slashes(agent_dir / profile.id)
        # gpg-agent может показать окно pinentry и ждать PIN.
        timeout = max(timeout, 120.0)
    else:
        env["RCLONE_CONFIG_SSHDRIVE_PASS"] = obscure(exe, password)

    if host_key and supports_host_key_pinning(exe):
        # rclone проверяет ключ хоста сам по пину и сам сужает список
        # алгоритмов (для RSA — до rsa-sha2-*). known_hosts_file в этом режиме
        # задавать нельзя: он имеет приоритет и отключает пин.
        env["RCLONE_CONFIG_SSHDRIVE_HOST_KEYS"] = host_key
    else:
        known_hosts = paths.known_hosts_file()
        if known_hosts.exists() and known_hosts.stat().st_size:
            env["RCLONE_CONFIG_SSHDRIVE_KNOWN_HOSTS_FILE"] = paths.forward_slashes(known_hosts)

    remote_path = profile.remote_path.strip()
    if remote_path and not remote_path.startswith("/") and ":" not in remote_path:
        remote_path = "/" + remote_path

    config_file = paths.rclone_config_file()
    if not config_file.exists():
        config_file.parent.mkdir(parents=True, exist_ok=True)
        config_file.write_text("", encoding="utf-8")

    args = [
        exe,
        "mount",
        f"sshdrive:{remote_path}",
        f"{drive}:",
        "--config",
        str(config_file),
        "--network-mode",
        "--volname",
        profile.name or "SSH Drive",
        "--vfs-cache-mode",
        "writes",
        "--dir-cache-time",
        "15s",
        "--attr-timeout",
        "3s",
        "--log-level",
        "NOTICE",
        "--stats",
        "0",
    ]
    if profile.read_only:
        args.append("--read-only")
    args.extend(extra_args)

    try:
        proc = subprocess.Popen(
            args,
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            creationflags=CREATE_NO_WINDOW,
        )
    except OSError as exc:
        raise RcloneError(f"Не удалось запустить rclone: {exc}") from exc

    handle = MountHandle(profile.id, drive.upper(), proc)

    def reader() -> None:
        assert proc.stdout is not None
        for line in proc.stdout:
            line = line.rstrip()
            if not line or is_benign_line(line):
                continue
            handle.output.append(line)
            del handle.output[:-200]
            if on_line:
                on_line(line)

    threading.Thread(target=reader, name=f"rclone-log-{profile.id}", daemon=True).start()

    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if proc.poll() is not None:
            time.sleep(0.3)  # дать дочитать вывод
            detail = "\n".join(handle.output[-12:]) or "rclone не вывел ничего"
            handle.stop(timeout=2)
            raise RcloneError(f"rclone завершился с кодом {proc.returncode}.\n{detail}")
        if drive_exists(drive):
            return handle
        time.sleep(0.25)

    detail = "\n".join(handle.output[-12:])
    handle.stop(timeout=3)
    raise RcloneError(
        f"Диск {drive}: не появился за {int(timeout)} с.\n{detail or 'rclone не вывел ничего'}"
    )
