"""SFTP-сервер SSH Share на asyncssh.

Отдаёт выбранную папку по SSH: пароль и/или публичные ключи, chroot внутри
папки, режим «только чтение» на пользователя.
"""

from __future__ import annotations

import asyncio
import os
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import Callable

import asyncssh

from .config import ShareConfig, ShareUser, burn_password_check, ensure_dummy_hash
from .hostkey import fingerprint, load_or_create

Log = Callable[[str, str], None]


class ShareError(Exception):
    """Не удалось запустить/остановить сервер."""


class AuthThrottle:
    """Защита от подбора пароля и от «засорения» сервера соединениями.

    * после max_failures неверных паролей с одного адреса за window секунд адрес
      блокируется на block_base секунд, при повторе срок удваивается (до block_max);
    * одновременно проверяемые пароли тоже считаются: неудачи плюс попытки «в
      полёте» не превышают max_failures, иначе параллельные соединения успевали бы
      проверить больше паролей до блокировки;
    * успешный вход счётчик НЕ обнуляет: иначе обладатель любого рабочего пароля
      (например, гостевого) мог бы бесконечно подбирать чужой с того же адреса;
      неудачи истекают сами через window секунд;
    * без входа с одного адреса можно держать не больше max_pending соединений,
      всего с одного адреса — не больше max_open (rclone открывает несколько
      соединений сразу, поэтому лимит общих соединений больше).

    Все вызовы идут из одного потока (цикл событий сервера).
    """

    def __init__(
        self,
        *,
        max_failures: int = 5,
        window: float = 300.0,
        block_base: float = 60.0,
        block_max: float = 900.0,
        max_pending: int = 10,
        max_open: int = 64,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.max_failures = max_failures
        self.window = window
        self.block_base = block_base
        self.block_max = block_max
        self.max_pending = max_pending
        self.max_open = max_open
        self._clock = clock
        self._failures: dict[str, list[float]] = {}
        self._inflight: dict[str, int] = {}
        self._blocked_until: dict[str, float] = {}
        self._strikes: dict[str, int] = {}
        self._pending: dict[str, int] = {}
        self._open: dict[str, int] = {}

    def blocked_for(self, ip: str) -> float:
        """Сколько секунд адрес ещё заблокирован (0 — не заблокирован)."""
        remaining = self._blocked_until.get(ip, 0.0) - self._clock()
        return remaining if remaining > 0 else 0.0

    def begin_attempt(self, ip: str) -> bool:
        """Можно ли проверять пароль сейчас. True резервирует место до end_attempt()."""
        if self.blocked_for(ip):
            return False
        now = self._clock()
        recent = sum(1 for t in self._failures.get(ip, []) if now - t < self.window)
        if recent + self._inflight.get(ip, 0) >= self.max_failures:
            return False
        self._inflight[ip] = self._inflight.get(ip, 0) + 1
        return True

    def end_attempt(self, ip: str, ok: bool) -> float:
        """Завершает попытку; для неверного пароля возвращает срок блокировки (или 0)."""
        self._dec(self._inflight, ip)
        return 0.0 if ok else self.failure(ip)

    def failure(self, ip: str) -> float:
        """Учитывает неверный пароль; возвращает срок блокировки (0 — не заблокирован)."""
        now = self._clock()
        recent = [t for t in self._failures.get(ip, []) if now - t < self.window]
        recent.append(now)
        if len(recent) < self.max_failures:
            self._failures[ip] = recent
            if len(self._failures) > 1024:
                self._prune(now)
            return 0.0
        self._failures.pop(ip, None)
        strikes = self._strikes.get(ip, 0) + 1
        self._strikes[ip] = strikes
        block = min(self.block_base * 2 ** (strikes - 1), self.block_max)
        self._blocked_until[ip] = now + block
        self._prune(now)
        return block

    def connection_opened(self, ip: str) -> bool:
        """False — соединение надо отклонить (лимит исчерпан)."""
        if self._pending.get(ip, 0) >= self.max_pending or self._open.get(ip, 0) >= self.max_open:
            return False
        self._pending[ip] = self._pending.get(ip, 0) + 1
        self._open[ip] = self._open.get(ip, 0) + 1
        return True

    def authenticated(self, ip: str) -> None:
        self._dec(self._pending, ip)

    def connection_closed(self, ip: str, authenticated: bool) -> None:
        if not authenticated:
            self._dec(self._pending, ip)
        self._dec(self._open, ip)

    @staticmethod
    def _dec(counter: dict[str, int], ip: str) -> None:
        left = counter.get(ip, 0) - 1
        if left > 0:
            counter[ip] = left
        else:
            counter.pop(ip, None)

    def _prune(self, now: float) -> None:
        """Не даём таблицам расти бесконечно."""
        for ip in [ip for ip, until in self._blocked_until.items() if until <= now]:
            if now - self._blocked_until[ip] > self.window:
                self._blocked_until.pop(ip, None)
                self._strikes.pop(ip, None)
        for ip in [ip for ip, times in self._failures.items() if not times or now - times[-1] >= self.window]:
            self._failures.pop(ip, None)


# Пауза после неверного пароля: замедляет перебор даже до блокировки.
FAIL_DELAY = 1.0

# scrypt берёт ~32 МиБ на проверку: отдельный маленький пул ограничивает память
# и процессор, сколько бы соединений ни пришло одновременно.
_HASH_POOL = ThreadPoolExecutor(max_workers=4, thread_name_prefix="share-scrypt")


def _local_path(sftp_path: bytes) -> str:
    text = os.fsdecode(sftp_path)
    if text[:1] == "/" and text[2:3] == ":":
        text = text[1:]
    if os.name == "nt":
        text = text.replace("/", "\\")
    return text


def _within(root: str, path: str) -> bool:
    root_n = os.path.normcase(os.path.abspath(root))
    path_n = os.path.normcase(os.path.abspath(path))
    try:
        return os.path.commonpath([root_n, path_n]) == root_n
    except ValueError:  # разные диски
        return False


class ConfinedSFTPServer(asyncssh.SFTPServer):
    """SFTP-сервер, запертый в папке (включая симлинки/ junctions)."""

    def __init__(self, chan, root: Path) -> None:
        self._root = os.path.realpath(str(root))
        super().__init__(chan, chroot=os.fsencode(self._root))

    def map_path(self, path: bytes) -> bytes:
        mapped = super().map_path(path)
        local = os.path.realpath(_local_path(mapped))
        if not _within(self._root, local):
            raise asyncssh.SFTPPermissionDenied
        return mapped


class ReadOnlySFTPServer(ConfinedSFTPServer):
    """То же, но любые изменения запрещены."""

    _write_flags = asyncssh.FXF_WRITE | asyncssh.FXF_CREAT | asyncssh.FXF_TRUNC | asyncssh.FXF_APPEND

    def open(self, path, pflags, attrs):
        if pflags & self._write_flags:
            raise asyncssh.SFTPPermissionDenied
        return super().open(path, pflags, attrs)

    def open56(self, path, desired_access, flags, attrs):
        if desired_access & (asyncssh.ACE4_WRITE_DATA | asyncssh.ACE4_APPEND_DATA):
            raise asyncssh.SFTPPermissionDenied
        disposition = flags & asyncssh.FXF_ACCESS_DISPOSITION
        if disposition != asyncssh.FXF_OPEN_EXISTING:
            raise asyncssh.SFTPPermissionDenied
        if flags & asyncssh.FXF_APPEND_DATA:
            raise asyncssh.SFTPPermissionDenied
        return super().open56(path, desired_access, flags, attrs)

    def _deny(self, *args, **kwargs):
        raise asyncssh.SFTPPermissionDenied

    mkdir = _deny
    remove = _deny
    rmdir = _deny
    rename = _deny
    posix_rename = _deny
    symlink = _deny
    link = _deny
    setstat = _deny
    fsetstat = _deny
    lsetstat = _deny


class _AuthServer(asyncssh.SSHServer):
    """Проверка пользователей по паролю и публичным ключам."""

    def __init__(
        self,
        users: dict[str, ShareUser],
        keys: dict[str, set[bytes]],
        connections: set,
        log: Log,
        throttle: AuthThrottle,
    ) -> None:
        self._users = users
        self._keys = keys
        self._connections = connections
        self._log = log
        self._throttle = throttle
        self._username = ""
        self._peer = ""
        self._ip = ""
        self._conn = None
        self._counted = False
        self._authenticated = False

    def connection_made(self, conn) -> None:
        self._conn = conn
        try:
            peername = conn.get_extra_info("peername")
            self._peer = str(peername or "")
            self._ip = str(peername[0]) if peername else ""
        except Exception:  # noqa: BLE001
            self._peer = self._ip = ""
        remaining = self._throttle.blocked_for(self._ip)
        if remaining:
            self._log(f"Отклонено (адрес заблокирован ещё {int(remaining)} с): {self._peer}", "warn")
            conn.abort()
            return
        if not self._throttle.connection_opened(self._ip):
            self._log(f"Отклонено (слишком много соединений): {self._peer}", "warn")
            conn.abort()
            return
        self._counted = True
        self._connections.add(conn)
        self._log(f"Подключение: {self._peer}", "info")

    def connection_lost(self, exc) -> None:
        if self._counted:
            self._throttle.connection_closed(self._ip, self._authenticated)
            self._connections.discard(self._conn)
            self._log(f"Отключение: {self._peer}", "dim")

    def auth_completed(self) -> None:
        self._authenticated = True
        self._throttle.authenticated(self._ip)

    def begin_auth(self, username: str) -> bool:
        self._username = username
        return True

    def password_auth_supported(self) -> bool:
        return any(user.has_password for user in self._users.values())

    async def validate_password(self, username: str, password: str) -> bool:
        if not self._throttle.begin_attempt(self._ip):
            return False
        user = self._users.get(username)
        loop = asyncio.get_running_loop()
        ok = False
        try:
            # scrypt считается вне цикла событий, чтобы не вешать остальные соединения.
            if user is not None:
                ok = await loop.run_in_executor(_HASH_POOL, user.check_password, password)
            else:  # то же время, что и для настоящего пользователя
                await loop.run_in_executor(_HASH_POOL, burn_password_check, password)
        finally:
            # Оборванная на середине попытка тоже считается неудачей.
            block = self._throttle.end_attempt(self._ip, ok)
        if ok:
            self._log(f"Вход по паролю: {username}@{self._peer}", "ok")
            return True
        self._log(f"Неудачный вход по паролю: {username}@{self._peer}", "warn")
        if block:
            self._log(f"Слишком много неверных паролей: {self._ip} заблокирован на {int(block)} с", "warn")
        await asyncio.sleep(FAIL_DELAY)
        if block and self._conn is not None:
            self._conn.abort()
        return False

    def public_key_auth_supported(self) -> bool:
        return any(self._keys.values())

    def validate_public_key(self, username: str, key: asyncssh.SSHKey) -> bool:
        # Неверные ключи в блокировку не считаем: клиент с несколькими ключами
        # честно перебирает их, а угадать открытый ключ нельзя.
        data = key.export_public_key()
        ok = data in self._keys.get(username, set())
        if ok:
            self._log(f"Вход по ключу: {username}@{self._peer}", "ok")
        else:
            self._log(f"Неудачный вход по ключу: {username}@{self._peer}", "warn")
        return ok


class ShareServer:
    """Управляет жизненным циклом SFTP-сервера в отдельном потоке."""

    def __init__(
        self, config: ShareConfig, log: Log | None = None, throttle: AuthThrottle | None = None
    ) -> None:
        self._config = config
        self._throttle = throttle or AuthThrottle()
        self._log = log or (lambda _message, _level: None)
        self._root = Path(config.folder)
        self._users = {user.name: user for user in config.users}
        self._keys = {
            user.name: {
                asyncssh.import_public_key(item).export_public_key()
                for item in user.keys
                if item.strip()
            }
            for user in config.users
        }
        self._host_key = None  # type: ignore[assignment]
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server = None
        self._ready = threading.Event()
        self._error = ""
        self.port = int(config.port)
        self._connections: set = set()

    @property
    def running(self) -> bool:
        return self._thread is not None and self._thread.is_alive() and bool(self._server)

    def fingerprint(self) -> str:
        if self._host_key is None:
            return ""
        return fingerprint(self._host_key)

    def start(self) -> None:
        if self.running:
            return
        if not self._root.is_dir():
            raise ShareError(f"Папка не найдена: {self._root}")
        try:
            ensure_dummy_hash()  # первая попытка с неизвестным именем не должна быть дольше
            self._host_key = load_or_create()
        except Exception as exc:  # noqa: BLE001
            raise ShareError(str(exc)) from exc

        self._ready.clear()
        self._error = ""
        self._server = None
        self._thread = threading.Thread(target=self._run, name="share-server", daemon=True)
        self._thread.start()
        if not self._ready.wait(15):
            self.stop()
            raise ShareError("Сервер не запустился за 15 секунд.")
        if self._error:
            self.stop()
            raise ShareError(self._error)

    def stop(self) -> None:
        loop = self._loop
        server = self._server
        if loop is not None and server is not None:
            try:
                loop.call_soon_threadsafe(self._shutdown)
            except RuntimeError:
                pass
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=10)
        self._thread = None
        self._server = None
        self._loop = None
        self.port = int(self._config.port)

    def _shutdown(self) -> None:
        if self._server is not None:
            try:
                self._server.close()
            except Exception:  # noqa: BLE001
                pass
        for conn in list(self._connections):
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
        self._connections.clear()

    def _run(self) -> None:
        loop = asyncio.new_event_loop()
        self._loop = loop
        asyncio.set_event_loop(loop)
        try:
            self._server = loop.run_until_complete(self._create_server())
            self.port = self._server.get_port()
            self._log(f"Сервер слушает {self._config.bind}:{self.port}", "ok")
            self._ready.set()
            loop.run_until_complete(self._server.wait_closed())
        except Exception as exc:  # noqa: BLE001
            self._error = f"{type(exc).__name__}: {exc}"
            self._log(f"Ошибка сервера: {self._error}", "err")
            self._ready.set()
        finally:
            try:
                loop.close()
            except Exception:  # noqa: BLE001
                pass

    async def _create_server(self):
        assert self._host_key is not None
        return await asyncssh.create_server(
            lambda: _AuthServer(
                self._users, self._keys, self._connections, self._log, self._throttle
            ),
            self._config.bind or "0.0.0.0",
            int(self._config.port),
            server_host_keys=[self._host_key],
            sftp_factory=self._sftp_factory,
            server_version="SSHShare",
            login_timeout=60,
        )

    def _sftp_factory(self, chan):
        username = str(chan.get_extra_info("username") or "")
        user = self._users.get(username)
        read_only = True if user is None else user.read_only
        cls = ReadOnlySFTPServer if read_only else ConfinedSFTPServer
        return cls(chan, self._root)
