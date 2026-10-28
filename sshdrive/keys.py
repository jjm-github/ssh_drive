"""Генерация, чтение и экспорт SSH-ключей (ed25519, формат OpenSSH)."""

from __future__ import annotations

import base64
import hashlib
import re
from pathlib import Path

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

from . import paths


_COMMENT_UNSAFE = re.compile(r"[^A-Za-z0-9@._+\-]")


class KeyError_(Exception):
    """Ошибка работы с ключом."""


def sanitize_comment(comment: str) -> str:
    """Комментарий публичного ключа: только безопасные символы, одна строка."""
    return _COMMENT_UNSAFE.sub("_", comment.strip())[:64]


def default_key_path() -> Path:
    return paths.keys_dir() / "id_ed25519"


def unique_path(base: Path) -> Path:
    if not base.exists() and not base.with_suffix(base.suffix + ".pub").exists():
        return base
    for index in range(2, 1000):
        candidate = base.with_name(f"{base.name}_{index}")
        if not candidate.exists() and not candidate.with_suffix(candidate.suffix + ".pub").exists():
            return candidate
    raise KeyError_(f"Не удалось подобрать имя файла рядом с {base}")


def generate(path: Path, comment: str, passphrase: str = "") -> str:
    """Создаёт пару ключей и возвращает строку публичного ключа."""
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    private = ed25519.Ed25519PrivateKey.generate()
    encryption = (
        serialization.BestAvailableEncryption(passphrase.encode("utf-8"))
        if passphrase
        else serialization.NoEncryption()
    )
    blob = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        encryption,
    )
    # Сначала создаём пустой файл и закрываем доступ другим пользователям,
    # и только потом пишем в него ключ (на Windows chmod права не меняет).
    path.touch()
    paths.restrict_to_owner(path)
    path.write_bytes(blob)

    public = private.public_key().public_bytes(
        serialization.Encoding.OpenSSH,
        serialization.PublicFormat.OpenSSH,
    ).decode("ascii")
    line = f"{public} {sanitize_comment(comment)}".strip()
    path.with_suffix(path.suffix + ".pub").write_text(line + "\n", encoding="utf-8")
    return line


def load(path: str | Path, passphrase: str = "") -> paramiko.PKey:
    path = Path(path)
    if not path.exists():
        raise KeyError_(f"Файл ключа не найден: {path}")
    try:
        # paramiko 5.x передаёт пароль в cryptography без кодирования,
        # поэтому передаём bytes напрямую (str там падает с TypeError).
        return paramiko.PKey.from_path(str(path), password=passphrase.encode("utf-8") or None)
    except paramiko.PasswordRequiredException as exc:
        raise KeyError_("Ключ зашифрован парольной фразой") from exc
    except paramiko.SSHException as exc:
        raise KeyError_(f"Не удалось прочитать ключ: {exc}") from exc
    except (ValueError, TypeError) as exc:
        text = str(exc).lower()
        if "not provided" in text or "password-protected" in text:
            raise KeyError_("Ключ зашифрован парольной фразой") from exc
        if passphrase:
            raise KeyError_("Неверная парольная фраза или неизвестный формат ключа") from exc
        raise KeyError_(f"Не удалось прочитать ключ: {exc}") from exc


def needs_passphrase(path: str | Path) -> bool:
    """Зашифрован ли приватный ключ парольной фразой."""
    try:
        data = Path(path).read_bytes()
    except OSError:
        return False
    loaders = (serialization.load_ssh_private_key, serialization.load_pem_private_key)
    for loader in loaders:
        try:
            loader(data, password=None)
            return False
        except TypeError:
            return True
        except Exception:  # формат не подошёл — пробуем другой загрузчик
            continue
    return False


def public_line(path: str | Path, passphrase: str = "") -> str:
    """Публичный ключ в одну строку, вычисленный из приватного.

    Файл .pub не доверенный: в нём может оказаться другой ключ или несколько
    строк, и всё это уехало бы в authorized_keys на сервере. Из .pub берём
    только комментарий, и лишь если ключ в нём совпадает с приватным.
    """
    path = Path(path)
    key = load(path, passphrase)
    line = f"{key.get_name()} {key.get_base64()}"
    pub_file = path.with_suffix(path.suffix + ".pub")
    try:
        lines = pub_file.read_text(encoding="utf-8", errors="replace").strip().splitlines()
        parts = lines[0].split(None, 2) if lines else []
    except OSError:
        parts = []
    if len(parts) == 3 and parts[0] == key.get_name() and parts[1] == key.get_base64():
        comment = sanitize_comment(parts[2])
        if comment:
            line = f"{line} {comment}"
    return line


def export_unencrypted_pem(path: str | Path, passphrase: str) -> str:
    """Незашифрованный PEM ключа — его понимает rclone (опция key_pem).

    Возвращается строкой и никогда не пишется на диск.
    """
    data = Path(path).read_bytes()
    password = passphrase.encode("utf-8") if passphrase else None
    try:
        private = serialization.load_ssh_private_key(data, password=password)
    except ValueError:
        private = serialization.load_pem_private_key(data, password=password)
    blob = private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    )
    return blob.decode("ascii")


def fingerprint(path: str | Path, passphrase: str = "") -> str:
    key = load(path, passphrase)
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")
