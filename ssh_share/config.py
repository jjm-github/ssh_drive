"""Конфигурация SSH Share: папка, порт и пользователи."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import re
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from sshdrive.secretstore import try_unprotect

from . import paths

USER_NAME_RE = re.compile(r"[A-Za-z0-9._-]{1,32}")

# Пароли пользователей хранятся не в обратимом виде, а как scrypt-хэш: серверу
# нужна только проверка. Параметры (память 32 МиБ, ~0,1 с) — компромисс между
# защитой от перебора украденного файла и нагрузкой на сервер.
MIN_PASSWORD_LENGTH = 10
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**15, 8, 1
_SCRYPT_MAXMEM = 128 * 1024 * 1024
_SCRYPT_LIMITS = (2**17, 16, 4)  # потолок параметров из файла (защита от «бомбы» в конфиге)


def check_new_password(plain: str) -> str | None:
    """Сообщение об ошибке для слишком слабого нового пароля или None."""
    if len(plain) < MIN_PASSWORD_LENGTH:
        return f"Пароль слишком короткий: нужно не меньше {MIN_PASSWORD_LENGTH} символов."
    if len(set(plain)) < 4:
        return "Пароль слишком простой: используйте больше разных символов."
    return None


def hash_password(plain: str) -> str:
    salt = os.urandom(16)
    digest = hashlib.scrypt(
        plain.encode("utf-8"), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P,
        maxmem=_SCRYPT_MAXMEM, dklen=32,
    )
    b64 = lambda raw: base64.b64encode(raw).decode("ascii")  # noqa: E731
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${b64(salt)}${b64(digest)}"


def verify_password_hash(plain: str, stored: str) -> bool:
    """Сверяет пароль с записью hash_password(); любой мусор в записи даёт False."""
    try:
        scheme, n, r, p, salt_b64, digest_b64 = stored.split("$")
        n, r, p = int(n), int(r), int(p)
        salt, expected = base64.b64decode(salt_b64), base64.b64decode(digest_b64)
        if scheme != "scrypt" or not (2 <= n <= _SCRYPT_LIMITS[0] and n & (n - 1) == 0):
            return False
        if not (1 <= r <= _SCRYPT_LIMITS[1] and 1 <= p <= _SCRYPT_LIMITS[2] and len(expected) == 32):
            return False
        actual = hashlib.scrypt(
            plain.encode("utf-8"), salt=salt, n=n, r=r, p=p, maxmem=_SCRYPT_MAXMEM, dklen=32
        )
    except (ValueError, TypeError):
        return False
    return hmac.compare_digest(actual, expected)


_DUMMY_HASH = ""


def ensure_dummy_hash() -> str:
    """Хэш-«пустышка» для неизвестных пользователей (считается один раз)."""
    global _DUMMY_HASH
    if not _DUMMY_HASH:
        _DUMMY_HASH = hash_password("dummy-password-for-timing")
    return _DUMMY_HASH


def burn_password_check(plain: str) -> None:
    """Тратит столько же времени, сколько реальная проверка (неизвестный пользователь)."""
    verify_password_hash(plain, ensure_dummy_hash())


@dataclass
class ShareUser:
    """Пользователь, которому разрешён доступ к папке."""

    name: str = ""
    password_enc: str = ""  # устаревшее: пароль под DPAPI (переносится в password_hash)
    keys: list[str] = field(default_factory=list)  # публичные ключи (OpenSSH, одна строка)
    read_only: bool = True
    password_hash: str = ""  # scrypt-хэш пароля

    @property
    def has_password(self) -> bool:
        return bool(self.password_hash or self.password_enc)

    def password(self) -> str:
        """Устаревшая запись: расшифрованный пароль (или пустая строка)."""
        return try_unprotect(self.password_enc) or ""

    def set_password(self, plain: str) -> None:
        self.password_hash = hash_password(plain) if plain else ""
        self.password_enc = ""

    def check_password(self, plain: str) -> bool:
        if self.password_hash:
            return verify_password_hash(plain, self.password_hash)
        if self.password_enc:
            expected = self.password()
            return bool(expected) and hmac.compare_digest(
                expected.encode("utf-8"), plain.encode("utf-8")
            )
        burn_password_check(plain)
        return False

    def migrate_password(self) -> bool:
        """Переносит старый пароль под DPAPI в scrypt-хэш. True, если запись изменилась."""
        if self.password_hash or not self.password_enc:
            return False
        plain = self.password()
        if not plain:
            return False
        self.set_password(plain)
        return True

    def auth_label(self) -> str:
        if self.has_password and self.keys:
            return "пароль+ключ"
        if self.has_password:
            return "пароль"
        if self.keys:
            return "ключ"
        return "нет входа"

    def access_label(self) -> str:
        return "чтение" if self.read_only else "чтение/запись"

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "ShareUser":
        known = {item.name for item in fields(cls)}
        values = {k: v for k, v in data.items() if k in known}
        keys = values.get("keys") or []
        values["keys"] = [str(key) for key in keys if str(key).strip()]
        return cls(**values)


@dataclass
class ShareConfig:
    folder: str = ""
    port: int = 2222
    bind: str = "0.0.0.0"
    users: list[ShareUser] = field(default_factory=list)

    def user(self, name: str) -> ShareUser | None:
        return next((user for user in self.users if user.name == name), None)

    def to_dict(self) -> dict:
        return {
            "folder": self.folder,
            "port": self.port,
            "bind": self.bind,
            "users": [user.to_dict() for user in self.users],
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ShareConfig":
        try:
            port = int(data.get("port", 2222))
        except (TypeError, ValueError):
            port = 2222
        bind = str(data.get("bind") or "0.0.0.0")
        if bind not in ("0.0.0.0", "127.0.0.1"):
            bind = "0.0.0.0"
        users: list[ShareUser] = []
        for item in data.get("users") or []:
            if not isinstance(item, dict):
                continue
            try:
                user = ShareUser.from_dict(item)
            except Exception:
                continue
            if USER_NAME_RE.fullmatch(user.name):
                users.append(user)
        return cls(
            folder=str(data.get("folder") or ""),
            port=port,
            bind=bind,
            users=users,
        )


class ConfigStore:
    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else paths.config_file()
        self.config = ShareConfig()
        self.load()

    def load(self) -> None:
        if not self.path.exists():
            self.config = ShareConfig()
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        if isinstance(raw, dict):
            self.config = ShareConfig.from_dict(raw)
        if any([user.migrate_password() for user in self.config.users]):
            try:
                self.save()
            except OSError:
                pass  # перенесётся при следующем сохранении

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self.config.to_dict(), ensure_ascii=False, indent=2)
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(payload, encoding="utf-8")
        os.replace(tmp, self.path)


def validate_share(config: ShareConfig) -> None:
    """Проверка настроек перед запуском сервера."""
    from .server import ShareError

    if not config.folder or not Path(config.folder).is_dir():
        raise ShareError("Укажите существующую папку для общего доступа.")
    if not (0 <= int(config.port) <= 65535):
        raise ShareError("Порт должен быть от 0 до 65535 (0 — выбрать свободный автоматически).")
    if not config.users:
        raise ShareError("Добавьте хотя бы одного пользователя.")
    names = set()
    for user in config.users:
        if not USER_NAME_RE.fullmatch(user.name):
            raise ShareError(
                f"Недопустимое имя пользователя «{user.name}»: разрешены латиница, "
                "цифры и символы . _ - (до 32 символов)."
            )
        if user.name.lower() in names:
            raise ShareError(f"Пользователь «{user.name}» указан дважды.")
        names.add(user.name.lower())
        if not user.has_password and not user.keys:
            raise ShareError(f"У пользователя «{user.name}» нет пароля или ключа.")
