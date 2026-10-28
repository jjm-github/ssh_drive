"""Вход по ключу из SSH-агента: настоящий paramiko против поддельных агента и сервера.

Агент говорит по протоколу ssh-agent (REQUEST_IDENTITIES / SIGN_REQUEST) на
Unix-сокете; paramiko на Linux находит его через SSH_AUTH_SOCK. На Windows тот же
код ходит к Pageant / именованному каналу OpenSSH, но протокол внутри одинаковый.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import socket
import struct
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

import paramiko
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sshdrive import paths, profiles, rclone, sshutil  # noqa: E402

REQUEST_IDENTITIES, IDENTITIES_ANSWER = 11, 12
SIGN_REQUEST, SIGN_RESPONSE, FAILURE = 13, 14, 5


class AgentKeyPair:
    def __init__(self, comment: str) -> None:
        self.private = ed25519.Ed25519PrivateKey.generate()
        self.comment = comment
        raw = self.private.public_key().public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        msg = paramiko.Message()
        msg.add_string("ssh-ed25519")
        msg.add_string(raw)
        self.blob = msg.asbytes()
        self.b64 = base64.b64encode(self.blob).decode("ascii")

    @property
    def line(self) -> str:
        return f"ssh-ed25519 {self.b64}"

    @property
    def fingerprint(self) -> str:
        digest = hashlib.sha256(self.blob).digest()
        return "SHA256:" + base64.b64encode(digest).decode().rstrip("=")


class FakeAgent:
    def __init__(self, path: str, pairs: list[AgentKeyPair]) -> None:
        self.pairs = pairs
        self.signed: list[str] = []
        self._sock = socket.socket(socket.AF_UNIX)
        self._sock.bind(path)
        self._sock.listen(5)
        threading.Thread(target=self._accept, daemon=True).start()

    def close(self) -> None:
        self._sock.close()

    def _accept(self) -> None:
        while True:
            try:
                conn, _ = self._sock.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    @staticmethod
    def _recv(conn: socket.socket, n: int) -> bytes:
        data = b""
        while len(data) < n:
            chunk = conn.recv(n - len(data))
            if not chunk:
                return b""
            data += chunk
        return data

    def _serve(self, conn: socket.socket) -> None:
        with conn:
            while True:
                header = self._recv(conn, 4)
                if not header:
                    return
                body = self._recv(conn, struct.unpack(">I", header)[0])
                reply = self._handle(body)
                conn.sendall(struct.pack(">I", len(reply)) + reply)

    def _handle(self, body: bytes) -> bytes:
        out = paramiko.Message()
        if body[0] == REQUEST_IDENTITIES:
            out.add_byte(bytes([IDENTITIES_ANSWER]))
            out.add_int(len(self.pairs))
            for pair in self.pairs:
                out.add_string(pair.blob)
                out.add_string(pair.comment)
            return out.asbytes()
        if body[0] == SIGN_REQUEST:
            request = paramiko.Message(body[1:])
            blob, data = request.get_binary(), request.get_binary()
            for pair in self.pairs:
                if pair.blob == blob:
                    self.signed.append(pair.b64)
                    inner = paramiko.Message()
                    inner.add_string("ssh-ed25519")
                    inner.add_string(pair.private.sign(data))
                    out.add_byte(bytes([SIGN_RESPONSE]))
                    out.add_string(inner.asbytes())
                    return out.asbytes()
        out.add_byte(bytes([FAILURE]))
        return out.asbytes()


class FakeSSHServer(paramiko.ServerInterface):
    """Пускает только по публичному ключу и запоминает, какие ключи предлагали."""

    def __init__(self, allowed_b64: str) -> None:
        self.allowed = allowed_b64
        self.offered: list[str] = []

    def check_auth_publickey(self, username, key):
        self.offered.append(key.get_base64())
        return paramiko.AUTH_SUCCESSFUL if key.get_base64() == self.allowed else paramiko.AUTH_FAILED

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"


def _host_key() -> paramiko.PKey:
    pem = ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()
    return paramiko.Ed25519Key.from_private_key(io.StringIO(pem))


class AgentTests(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        env = mock.patch.dict(
            os.environ,
            {
                "APPDATA": str(self.root / "roaming"),
                "LOCALAPPDATA": str(self.root / "local"),
                "SSH_AUTH_SOCK": str(self.root / "agent.sock"),
            },
        )
        env.start()
        self.addCleanup(env.stop)
        self.pairs = [AgentKeyPair("gpg: auth subkey"), AgentKeyPair("other\x1b[31m key")]
        self.agent = FakeAgent(os.environ["SSH_AUTH_SOCK"], self.pairs)
        self.addCleanup(self.agent.close)

    def _serve_ssh(self, allowed: AgentKeyPair) -> tuple[int, FakeSSHServer]:
        sock = socket.socket()
        sock.bind(("127.0.0.1", 0))
        sock.listen(1)
        server = FakeSSHServer(allowed.b64)
        host_key = _host_key()

        def run() -> None:
            conn, _ = sock.accept()
            transport = paramiko.Transport(conn)
            transport.add_server_key(host_key)
            try:
                transport.start_server(server=server)
                transport.accept(5)
            except Exception:  # noqa: BLE001 - клиент мог оборвать рукопожатие
                pass
            finally:
                transport.close()
                sock.close()

        threading.Thread(target=run, daemon=True).start()
        return sock.getsockname()[1], server

    # --- список ключей -----------------------------------------------------
    def test_list_agent_keys(self) -> None:
        identities = sshutil.list_agent_keys()
        self.assertEqual([i.line for i in identities], [p.line for p in self.pairs])
        self.assertEqual(identities[0].fingerprint, self.pairs[0].fingerprint)
        self.assertEqual(identities[0].comment, "gpg: auth subkey")
        self.assertNotIn("\x1b", identities[1].comment)  # управляющие символы вычищены

    def test_no_agent(self) -> None:
        self.agent.close()
        os.unlink(os.environ["SSH_AUTH_SOCK"])
        with self.assertRaises(sshutil.SSHError) as ctx:
            sshutil.list_agent_keys()
        self.assertIn("enable-putty-support", str(ctx.exception))

    # --- вход ---------------------------------------------------------------
    def test_login_with_selected_agent_key_offers_only_that_key(self) -> None:
        wanted = self.pairs[1]
        port, server = self._serve_ssh(wanted)
        known = self.root / "known_hosts"
        info = sshutil.connect(
            "127.0.0.1", port, "u", agent_key=wanted.line,
            known_hosts=known, confirm=lambda *_a: True,
        )
        info.close()
        self.assertEqual(server.offered, [wanted.b64])  # первый ключ серверу не предлагали
        self.assertEqual(self.agent.signed, [wanted.b64])

    def test_login_fails_if_selected_key_is_rejected(self) -> None:
        port, server = self._serve_ssh(self.pairs[0])
        with self.assertRaises(sshutil.SSHError) as ctx:
            sshutil.connect(
                "127.0.0.1", port, "u", agent_key=self.pairs[1].line,
                known_hosts=self.root / "known_hosts", confirm=lambda *_a: True,
            )
        self.assertIn("отклонил вход", str(ctx.exception))
        self.assertEqual(server.offered, [self.pairs[1].b64])  # другой ключ не подставляли

    def test_selected_key_missing_from_agent(self) -> None:
        stranger = AgentKeyPair("stranger")
        with self.assertRaises(sshutil.SSHError) as ctx:
            sshutil.connect("127.0.0.1", 1, "u", agent_key=stranger.line)
        self.assertIn("нет в SSH-агенте", str(ctx.exception))

    def test_test_login_reports_server_info_via_agent(self) -> None:
        port, _server = self._serve_ssh(self.pairs[0])
        with mock.patch.object(sshutil, "home_dir", return_value="/home/u"):
            info = sshutil.test_login(
                "127.0.0.1", port, "u", agent_key=self.pairs[0].line,
                known_hosts=self.root / "known_hosts", confirm=lambda *_a: True,
            )
        self.assertEqual(info["home"], "/home/u")
        self.assertTrue(str(info["host_key"]).startswith("ssh-ed25519 "))

    # --- rclone ----------------------------------------------------------------
    def test_mount_env_for_agent(self) -> None:
        profile = profiles.Profile(
            id="abc123", host="h", user="u", auth="agent", agent_key=self.pairs[0].line
        )
        seen: dict = {}

        def fake_popen(args, env=None, **_kw):
            seen["env"] = env
            raise OSError("stop here")

        with mock.patch.object(rclone, "find_exe", return_value="rclone.exe"), \
                mock.patch.object(rclone, "drive_exists", return_value=False), \
                mock.patch.object(rclone.subprocess, "Popen", fake_popen):
            with self.assertRaises(rclone.RcloneError):
                rclone.mount(profile, drive="Z")

        env = seen["env"]
        self.assertEqual(env["RCLONE_CONFIG_SSHDRIVE_KEY_USE_AGENT"], "true")
        key_file = env["RCLONE_CONFIG_SSHDRIVE_KEY_FILE"]
        self.assertTrue(key_file.endswith("/agent/abc123"))
        self.assertFalse(Path(key_file).exists(), "приватного файла быть не должно")
        pub = Path(key_file + ".pub")
        self.assertEqual(pub.read_text().strip(), self.pairs[0].line)
        self.assertNotIn("RCLONE_CONFIG_SSHDRIVE_PASS", env)
        self.assertNotIn("RCLONE_CONFIG_SSHDRIVE_KEY_PEM", env)
        self.assertEqual(Path(pub).parent, paths.agent_dir())

    def test_mount_without_agent_key_is_refused(self) -> None:
        profile = profiles.Profile(id="abc123", host="h", user="u", auth="agent")
        with mock.patch.object(rclone, "find_exe", return_value="rclone.exe"), \
                mock.patch.object(rclone, "drive_exists", return_value=False):
            with self.assertRaises(rclone.RcloneError):
                rclone.mount(profile, drive="Z")


class AgentProfileTests(unittest.TestCase):
    def test_agent_mode_and_label(self) -> None:
        profile = profiles.Profile(auth="agent", agent_key="ssh-ed25519 AAAAC3Nza")
        self.assertEqual((profile.auth, profile.auth_label), ("agent", "агент"))
        self.assertEqual(profile.agent_key, "ssh-ed25519 AAAAC3Nza")

    def test_garbage_agent_key_is_dropped(self) -> None:
        for bad in ("ssh-ed25519 AAAA\nssh-rsa BBBB", "command=x ssh-rsa AAAA", "ssh-ed25519 AAAA x'y", 5):
            self.assertEqual(profiles.Profile(agent_key=bad).agent_key, "", repr(bad))

    def test_roundtrip_through_dict(self) -> None:
        profile = profiles.Profile(auth="agent", agent_key="ssh-rsa AAAAB3Nza==", agent_comment="card")
        again = profiles.Profile.from_dict(profile.to_dict())
        self.assertEqual((again.auth, again.agent_key, again.agent_comment), ("agent", "ssh-rsa AAAAB3Nza==", "card"))


if __name__ == "__main__":
    unittest.main()
