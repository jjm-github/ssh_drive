"""SSH-операции: проверка ключа хоста, вход, установка публичного ключа."""

from __future__ import annotations

import base64
import hashlib
import re
import shlex
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

import paramiko

ConfirmHostKey = Callable[[str, str, str], bool]
ConfirmAdmin = Callable[[], bool]

# Строго одна строка: тип, base64 и необязательный безопасный комментарий.
_PUBKEY_RE = re.compile(
    r"(?:ssh-ed25519|ssh-rsa|ecdsa-sha2-nistp(?:256|384|521)) "
    r"[A-Za-z0-9+/]+={0,3}(?: [A-Za-z0-9@._+\-]{1,64})?"
)


# Время на вход через агента: gpg-agent может показать окно pinentry и ждать PIN.
AGENT_AUTH_TIMEOUT = 120.0

NO_AGENT_MESSAGE = (
    "SSH-агент не найден или в нём нет ключей. Для gpg4win включите в gpg-agent.conf "
    "«enable-putty-support» (Pageant) или «enable-win32-openssh-support», перезапустите "
    "агент (gpgconf --kill gpg-agent) и проверьте, что ключ разрешён в sshcontrol."
)


class SSHError(Exception):
    """Понятная пользователю ошибка SSH."""


class HostKeyMismatch(SSHError):
    """Ключ хоста не совпадает с сохранённым (возможна MITM-атака)."""


class AuthCancelled(SSHError):
    """Пользователь отказался доверять новому ключу хоста."""


def fingerprint(key: paramiko.PKey) -> str:
    digest = hashlib.sha256(key.asbytes()).digest()
    return "SHA256:" + base64.b64encode(digest).decode("ascii").rstrip("=")


@dataclass(frozen=True)
class AgentIdentity:
    """Открытая часть ключа, который держит SSH-агент."""

    key_type: str
    base64: str
    fingerprint: str
    comment: str

    @property
    def line(self) -> str:
        """«тип base64» — то, что хранится в профиле."""
        return f"{self.key_type} {self.base64}"


def _open_agent() -> tuple[paramiko.Agent, list[paramiko.AgentKey]]:
    """Подключается к агенту (Pageant, затем OpenSSH-агент) и читает ключи."""
    try:
        agent = paramiko.Agent()
        keys = list(agent.get_keys())
    except (paramiko.SSHException, OSError) as exc:
        raise SSHError(f"Не удалось обратиться к SSH-агенту: {exc}") from exc
    if not keys:
        agent.close()
        raise SSHError(NO_AGENT_MESSAGE)
    return agent, keys


def list_agent_keys() -> list[AgentIdentity]:
    """Ключи, доступные в SSH-агенте (только типы, которые умеет программа)."""
    agent, keys = _open_agent()
    try:
        result = []
        for key in keys:
            line = f"{key.get_name()} {key.get_base64()}"
            if not _PUBKEY_RE.fullmatch(line):
                continue
            comment = "".join(ch for ch in (key.comment or "") if ch.isprintable())[:80]
            result.append(AgentIdentity(key.get_name(), key.get_base64(), fingerprint(key), comment))
        return result
    finally:
        agent.close()


def _agent_pkey(agent_key: str) -> tuple[paramiko.Agent, paramiko.AgentKey]:
    """Ключ из агента, точно совпадающий с выбранным в профиле.

    Другие ключи агента не предлагаются серверу: иначе вход мог бы пройти под
    не тем ключом или исчерпать лимит попыток (MaxAuthTries).
    """
    agent, keys = _open_agent()
    wanted = agent_key.split()[-1]
    for key in keys:
        if key.get_base64() == wanted:
            return agent, key
    agent.close()
    raise SSHError(
        "Выбранного ключа нет в SSH-агенте (возможно, смарт-карта не вставлена "
        "или ключ удалён). Выберите ключ заново в профиле."
    )


def _hostkey_name(host: str, port: int) -> str:
    """Имя хоста в формате known_hosts (как в OpenSSH)."""
    return host if int(port) == 22 else f"[{host}]:{int(port)}"


def _save_verified_key(path: Path, hostname: str, key: paramiko.PKey) -> None:
    """Оставляет для хоста ровно один ключ — проверенный.

    Go-клиент внутри rclone строго сверяет ключ с known_hosts: если для хоста
    лежат ещё и записи других типов (например, старый RSA рядом с новым
    ed25519), он падает с «knownhosts: key mismatch». Поэтому чистим лишнее.
    """
    hosts = paramiko.HostKeys()
    if path.exists():
        hosts.load(str(path))
    hosts.pop(hostname, None)
    hosts.add(hostname, key.get_name(), key)
    path.parent.mkdir(parents=True, exist_ok=True)
    hosts.save(str(path))


class _TOFUPolicy(paramiko.MissingHostKeyPolicy):
    """Спрашивает подтверждение у пользователя и запоминает ключ хоста."""

    def __init__(self, known_hosts: Path | None, confirm: ConfirmHostKey | None) -> None:
        self._path = Path(known_hosts) if known_hosts else None
        self._confirm = confirm

    def missing_host_key(self, client, hostname, key):  # noqa: ARG002 - API paramiko
        fp = fingerprint(key)
        if self._path is None or self._confirm is None:
            raise HostKeyMismatch(f"Неизвестный ключ хоста {hostname} ({fp})")

        if not self._confirm(hostname, key.get_name(), fp):
            raise AuthCancelled(f"Ключ хоста {hostname} отклонён пользователем")
        # Сюда paramiko попадает только если для хоста нет НИ ОДНОГО ключа, а при
        # несовпадении бросает BadHostKeyException, поэтому заменять тут нечего.
        hosts = paramiko.HostKeys()
        if self._path.exists():
            hosts.load(str(self._path))
        hosts.pop(hostname, None)
        hosts.add(hostname, key.get_name(), key)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        hosts.save(str(self._path))


def connect(
    host: str,
    port: int,
    user: str,
    *,
    password: str | None = None,
    pkey: paramiko.PKey | None = None,
    agent_key: str | None = None,
    known_hosts: Path | str | None = None,
    confirm: ConfirmHostKey | None = None,
    timeout: float = 20.0,
) -> paramiko.SSHClient:
    """Подключается по SSH, проверяя ключ хоста через known_hosts.

    agent_key — «тип base64» ключа из SSH-агента; тогда пароль и pkey не нужны.
    """
    client = paramiko.SSHClient()
    known_path = Path(known_hosts) if known_hosts else None
    try:
        if known_path and known_path.exists():
            client.load_host_keys(str(known_path))
    except Exception as exc:  # noqa: BLE001 - файл мог быть повреждён
        client.close()
        raise SSHError(f"Не удалось прочитать {known_path}: {exc}") from exc
    client.set_missing_host_key_policy(_TOFUPolicy(known_path, confirm))

    agent = None
    auth_timeout = timeout
    if agent_key:
        try:
            agent, pkey = _agent_pkey(agent_key)
        except BaseException:
            client.close()
            raise
        password = None
        auth_timeout = max(timeout, AGENT_AUTH_TIMEOUT)

    try:
        client.connect(
            hostname=host,
            port=int(port),
            username=user,
            password=password or None,
            pkey=pkey,
            timeout=timeout,
            banner_timeout=timeout,
            auth_timeout=auth_timeout,
            look_for_keys=False,
            allow_agent=False,
        )
    except paramiko.BadHostKeyException as exc:
        client.close()
        raise HostKeyMismatch(
            f"Ключ хоста {host}:{port} изменился!\n"
            f"  сохранённый: {fingerprint(exc.expected_key)}\n"
            f"  полученный:  {fingerprint(exc.key)}\n"
            "Если это ожидаемо — удалите запись через «Сервис → Известные хосты»."
        ) from exc
    except paramiko.AuthenticationException as exc:
        client.close()
        raise SSHError(
            "Сервер отклонил вход. Проверьте логин, пароль/ключ и что вход по SSH разрешён."
        ) from exc
    except (OSError, paramiko.SSHException) as exc:
        client.close()
        raise SSHError(f"Не удалось подключиться к {host}:{port}: {exc}") from exc
    except AuthCancelled:
        client.close()
        raise
    except Exception:
        client.close()
        raise
    finally:
        # Подпись нужна только во время входа; дальше агент не используется.
        if agent is not None:
            agent.close()

    # Запоминаем именно тот ключ, который реально использовался, и убираем
    # устаревшие записи других типов — иначе rclone (Go known_hosts) ругается
    # «key mismatch».
    if known_path is not None:
        try:
            transport = client.get_transport()
            server_key = transport.get_remote_server_key() if transport else None
            if server_key is not None:
                _save_verified_key(
                    known_path, _hostkey_name(host, int(port)), server_key
                )
        except Exception:  # noqa: BLE001 - не критично для подключения
            pass
    return client


def run(client: paramiko.SSHClient, command: str, timeout: float = 30.0) -> tuple[int, str, str]:
    """Выполняет команду и возвращает (код, stdout, stderr)."""
    _stdin, stdout, stderr = client.exec_command(command, timeout=timeout)
    out = stdout.read().decode("utf-8", "replace")
    err = stderr.read().decode("utf-8", "replace")
    code = stdout.channel.recv_exit_status()
    return code, out, err


def home_dir(client: paramiko.SSHClient) -> str:
    sftp = client.open_sftp()
    try:
        return sftp.normalize(".")
    finally:
        sftp.close()


def validate_public_key(pubkey: str) -> str:
    """Проверяет, что это ровно один публичный ключ, и возвращает его строку.

    Ключ попадает в команду на сервере (POSIX shell или PowerShell), поэтому
    любые переводы строк, кавычки и опции authorized_keys недопустимы.
    """
    line = pubkey.strip()
    if not _PUBKEY_RE.fullmatch(line):
        raise SSHError(
            "Публичный ключ имеет неожиданный формат (нужна одна строка вида "
            "«ssh-ed25519 AAAA… комментарий») — на сервер он не отправлен."
        )
    return line


def _posix_install_command(pubkey: str) -> str:
    q = shlex.quote(validate_public_key(pubkey))
    auth = '"$HOME/.ssh/authorized_keys"'
    return (
        'umask 077; '
        'mkdir -p "$HOME/.ssh"; '
        f'touch {auth}; '
        f'if ! grep -qxF -- {q} {auth}; then printf "%s\\n" {q} >> {auth}; fi; '
        'chmod 700 "$HOME/.ssh"; '
        f'chmod 600 {auth}; '
        f'grep -qxF -- {q} {auth} && echo SSHDRIVE_OK'
    )


def _windows_install_script(pubkey: str, write_admin: bool = False) -> str:
    key = validate_public_key(pubkey).replace("'", "''")
    admin_flag = "$true" if write_admin else "$false"
    return f"""
$ErrorActionPreference = 'Stop'
$key = '{key}'
$writeAdmin = {admin_flag}
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($isAdmin) {{ Write-Output 'SSHDRIVE_ADMIN_SESSION' }}
$targets = @(Join-Path $env:USERPROFILE '.ssh\\authorized_keys')
if ($isAdmin -and $writeAdmin) {{ $targets += (Join-Path $env:ProgramData 'ssh\\administrators_authorized_keys') }}
foreach ($file in $targets) {{
    $dir = Split-Path -Parent $file
    if (-not (Test-Path $dir)) {{ New-Item -ItemType Directory -Force -Path $dir | Out-Null }}
    if (-not (Test-Path $file)) {{ New-Item -ItemType File -Force -Path $file | Out-Null }}
    if (-not (Select-String -Path $file -SimpleMatch -Quiet -Pattern $key)) {{
        Add-Content -Path $file -Value $key -Encoding ascii
    }}
    if ($isAdmin -and ($file -like '*administrators_authorized_keys')) {{
        icacls $file /inheritance:r /grant '*S-1-5-32-544:F' /grant '*S-1-5-18:F' | Out-Null
    }}
    Write-Output ("updated: " + $file)
}}
Write-Output 'SSHDRIVE_OK'
"""


def _run_powershell(client: paramiko.SSHClient, script: str) -> tuple[int, str, str]:
    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    command = (
        "powershell -NoProfile -NonInteractive -ExecutionPolicy Bypass "
        f"-EncodedCommand {encoded}"
    )
    return run(client, command, timeout=60.0)


def install_public_key(
    client: paramiko.SSHClient,
    pubkey: str,
    confirm_admin: ConfirmAdmin | None = None,
) -> str:
    """Добавляет публичный ключ в authorized_keys на сервере (идемпотентно).

    Пробует POSIX-команду, затем PowerShell (сервер Windows с OpenSSH).
    Общий файл administrators_authorized_keys на Windows-сервере трогается
    только если confirm_admin() вернул True: ключ из него пускает под любой
    административной учётной записью сервера.
    """
    pubkey = validate_public_key(pubkey)
    code, out, err = run(client, _posix_install_command(pubkey))
    if code == 0 and "SSHDRIVE_OK" in out:
        return "ключ добавлен в ~/.ssh/authorized_keys"

    code2, out2, err2 = _run_powershell(client, _windows_install_script(pubkey))
    if "SSHDRIVE_OK" not in out2:
        raise SSHError(
            "Не удалось добавить ключ в authorized_keys.\n"
            f"POSIX-попытка: код {code}, {err.strip()[:300]}\n"
            f"PowerShell-попытка: код {code2}, {(err2 or out2).strip()[:300]}"
        )

    note = ""
    if "SSHDRIVE_ADMIN_SESSION" in out2:
        if confirm_admin is not None and confirm_admin():
            code3, out3, err3 = _run_powershell(client, _windows_install_script(pubkey, True))
            if "SSHDRIVE_OK" not in out3:
                raise SSHError(
                    "Не удалось записать administrators_authorized_keys: "
                    f"код {code3}, {(err3 or out3).strip()[:300]}"
                )
            out2 = out3
        else:
            note = "\nadministrators_authorized_keys не изменён"
    lines = [ln.strip() for ln in out2.splitlines() if ln.strip().startswith("updated:")]
    return ("\n".join(lines) or "ключ добавлен") + note


def test_login(
    host: str,
    port: int,
    user: str,
    *,
    password: str | None = None,
    pkey: paramiko.PKey | None = None,
    agent_key: str | None = None,
    known_hosts: Path | str | None = None,
    confirm: ConfirmHostKey | None = None,
) -> dict[str, object]:
    """Проверяет вход и возвращает сведения о сервере и ключе хоста."""
    client = connect(
        host, port, user, password=password, pkey=pkey, agent_key=agent_key,
        known_hosts=known_hosts, confirm=confirm,
    )
    try:
        transport = client.get_transport()
        home = home_dir(client)
        version = transport.remote_version if transport else ""
        server_key = transport.get_remote_server_key() if transport else None
        key_type = server_key.get_name() if server_key else ""
        return {
            "home": home,
            "version": version,
            "key_type": key_type,
            "host_key": (
                f"{key_type} {server_key.get_base64()}" if server_key else ""
            ),
            "fingerprint": fingerprint(server_key) if server_key else "",
        }
    finally:
        client.close()
