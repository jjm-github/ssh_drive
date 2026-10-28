"""Профили подключений (JSON в %APPDATA%\\SSHDrive\\profiles.json)."""

from __future__ import annotations

import json
import os
import re
import uuid
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path

from . import paths

_ID_RE = re.compile(r"[A-Za-z0-9_-]{1,32}")
# «тип base64» публичного ключа, выбранного в SSH-агенте
_AGENT_KEY_RE = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) [A-Za-z0-9+/]+={0,3}"
)
AUTH_MODES = ("key", "password", "agent")


def _drive_letter(value: object) -> str:
    """Буква диска A-Z или пустая строка (значение приходит из JSON)."""
    letter = str(value or "").strip().upper()[:1]
    return letter if "A" <= letter <= "Z" else ""


@dataclass
class Profile:
    """Одно подключение: сервер + способ входа + буква диска."""

    id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    name: str = ""
    host: str = ""
    port: int = 22
    user: str = ""
    auth: str = "key"  # "key" | "password" | "agent"
    key_path: str = ""
    agent_key: str = ""  # «тип base64» ключа из SSH-агента (auth = "agent")
    agent_comment: str = ""  # только для показа в интерфейсе
    remote_path: str = ""
    drive: str = ""  # пусто = выбрать автоматически
    read_only: bool = False
    auto_connect: bool = False  # подключать при старте программы
    last_drive: str = ""  # буква, которую занимал диск в прошлый раз
    extra_opts: str = ""
    save_secret: bool = False
    password_enc: str = ""
    passphrase_enc: str = ""

    def __post_init__(self) -> None:
        # id приходит из JSON и используется как идентификатор строки и потока.
        if not isinstance(self.id, str) or not _ID_RE.fullmatch(self.id):
            self.id = uuid.uuid4().hex[:12]
        self.port = int(self.port or 22)
        self.drive = _drive_letter(self.drive)
        self.last_drive = _drive_letter(self.last_drive)
        if self.auth not in AUTH_MODES:
            self.auth = "key"
        self.agent_key = str(self.agent_key or "").strip()
        if not _AGENT_KEY_RE.fullmatch(self.agent_key):
            self.agent_key = ""
        self.agent_comment = str(self.agent_comment or "")[:80]

    # --- удобные представления для таблицы ---------------------------------
    @property
    def title(self) -> str:
        return self.name or f"{self.user}@{self.host}"

    @property
    def target(self) -> str:
        return f"{self.user}@{self.host}:{self.port}"

    @property
    def auth_label(self) -> str:
        return {"key": "ключ", "agent": "агент"}.get(self.auth, "пароль")

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict) -> "Profile":
        known = {f.name for f in fields(cls)}
        return cls(**{k: v for k, v in data.items() if k in known})


class ProfileStore:
    """Простое хранилище списка профилей с атомарной записью."""

    def __init__(self, path: Path | None = None) -> None:
        self.path = Path(path) if path else paths.profiles_file()
        self.profiles: list[Profile] = []
        self.load()

    def load(self) -> None:
        self.profiles = []
        if not self.path.exists():
            return
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return
        for item in raw.get("profiles", []):
            if isinstance(item, dict):
                try:
                    self.profiles.append(Profile.from_dict(item))
                except Exception:
                    continue

    def save(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"version": 1, "profiles": [p.to_dict() for p in self.profiles]}
        tmp = self.path.with_suffix(".json.tmp")
        tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def get(self, profile_id: str) -> Profile | None:
        return next((p for p in self.profiles if p.id == profile_id), None)

    def add(self, profile: Profile) -> None:
        self.profiles.append(profile)
        self.save()

    def update(self, profile: Profile) -> None:
        for index, existing in enumerate(self.profiles):
            if existing.id == profile.id:
                self.profiles[index] = profile
                break
        else:
            self.profiles.append(profile)
        self.save()

    def delete(self, profile_id: str) -> None:
        self.profiles = [p for p in self.profiles if p.id != profile_id]
        self.save()
