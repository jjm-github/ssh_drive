"""SSH Share: хэширование паролей, защита от подбора, лимиты соединений, ключ сервера."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import asyncssh
import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from ssh_share import config as share_config  # noqa: E402
from ssh_share import hostkey, server as share_server  # noqa: E402
from ssh_share.config import (  # noqa: E402
    ConfigStore,
    ShareConfig,
    ShareUser,
    check_new_password,
    hash_password,
    verify_password_hash,
)
from ssh_share.server import AuthThrottle, ShareServer  # noqa: E402

GOOD = "correct-horse-battery"


class TempEnv(unittest.TestCase):
    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        patcher = mock.patch.dict(
            os.environ, {"APPDATA": str(self.root / "roaming"), "LOCALAPPDATA": str(self.root / "local")}
        )
        patcher.start()
        self.addCleanup(patcher.stop)


# --- пароли ---------------------------------------------------------------------
class PasswordHashTests(unittest.TestCase):
    def test_roundtrip_and_uniqueness(self) -> None:
        a, b = hash_password(GOOD), hash_password(GOOD)
        self.assertNotEqual(a, b, "соль должна быть случайной")
        self.assertTrue(a.startswith("scrypt$"))
        self.assertTrue(verify_password_hash(GOOD, a))
        self.assertFalse(verify_password_hash(GOOD + "x", a))
        self.assertNotIn(GOOD, a)

    def test_garbage_and_hostile_records_are_rejected(self) -> None:
        good = hash_password(GOOD)
        salt, digest = good.split("$")[4:]
        for bad in (
            "", "plain-text", "scrypt$1$1$1$AA==$AA==",
            f"scrypt$3$8$1${salt}${digest}",             # n не степень двойки
            f"scrypt${2**30}$8$1${salt}${digest}",       # «бомба» по памяти
            f"scrypt$32768$999$1${salt}${digest}",
            f"md5$32768$8$1${salt}${digest}",
            f"scrypt$32768$8$1${salt}$AAAA",             # короткий дайджест
            "scrypt$x$y$z$a$b",
        ):
            self.assertFalse(verify_password_hash(GOOD, bad), bad)

    def test_new_password_policy(self) -> None:
        self.assertIsNotNone(check_new_password("short"))
        self.assertIsNotNone(check_new_password("aaaaaaaaaaaa"))
        self.assertIsNone(check_new_password(GOOD))

    def test_user_checks_hash_and_legacy_record(self) -> None:
        user = ShareUser(name="u")
        user.set_password(GOOD)
        self.assertEqual(user.password_enc, "")
        self.assertTrue(user.has_password and user.check_password(GOOD))
        self.assertFalse(user.check_password("nope"))
        legacy = ShareUser(name="old", password_enc="dpapi-blob")
        with mock.patch.object(share_config, "try_unprotect", return_value="legacy-pass"):
            self.assertTrue(legacy.check_password("legacy-pass"))
            self.assertFalse(legacy.check_password("other"))
        self.assertFalse(ShareUser(name="none").check_password("anything"))


class MigrationTests(TempEnv):
    def test_dpapi_password_becomes_hash_on_load(self) -> None:
        path = self.root / "config.json"
        path.write_text(json.dumps({
            "folder": str(self.root), "port": 2222, "bind": "127.0.0.1",
            "users": [{"name": "old", "password_enc": "v2:blob", "keys": [], "read_only": True}],
        }))
        with mock.patch.object(share_config, "try_unprotect", return_value="legacy-pass-123"):
            store = ConfigStore(path)
        user = store.config.users[0]
        self.assertEqual(user.password_enc, "")
        self.assertTrue(verify_password_hash("legacy-pass-123", user.password_hash))
        on_disk = json.loads(path.read_text())["users"][0]
        self.assertEqual(on_disk["password_enc"], "")
        self.assertNotIn("legacy-pass-123", path.read_text())
        self.assertTrue(on_disk["password_hash"].startswith("scrypt$"))

    def test_unreadable_legacy_password_is_kept_not_lost(self) -> None:
        path = self.root / "config.json"
        path.write_text(json.dumps({"users": [{"name": "old", "password_enc": "blob"}]}))
        with mock.patch.object(share_config, "try_unprotect", return_value=None):
            store = ConfigStore(path)
        self.assertEqual(store.config.users[0].password_enc, "blob")


# --- ограничитель ---------------------------------------------------------------
class ThrottleTests(unittest.TestCase):
    def setUp(self) -> None:
        self.now = [1000.0]
        self.t = AuthThrottle(clock=lambda: self.now[0])

    def test_blocks_after_five_failures_and_doubles(self) -> None:
        for _ in range(4):
            self.assertEqual(self.t.failure("1.2.3.4"), 0.0)
        self.assertEqual(self.t.failure("1.2.3.4"), 60.0)
        self.assertAlmostEqual(self.t.blocked_for("1.2.3.4"), 60.0)
        self.assertEqual(self.t.blocked_for("5.6.7.8"), 0.0, "чужой адрес не страдает")
        self.now[0] += 61
        self.assertEqual(self.t.blocked_for("1.2.3.4"), 0.0)
        for _ in range(4):
            self.t.failure("1.2.3.4")
        self.assertEqual(self.t.failure("1.2.3.4"), 120.0, "срок удваивается")

    def test_block_is_capped(self) -> None:
        last = 0.0
        for _ in range(12):
            for _ in range(5):
                last = self.t.failure("9.9.9.9") or last
            self.now[0] += 10_000
        self.assertEqual(last, 900.0)

    def test_successful_login_does_not_reset_failures(self) -> None:
        # Иначе любой рабочий пароль с того же адреса обнулял бы счётчик подбора.
        for _ in range(4):
            self.assertTrue(self.t.begin_attempt("a"))
            self.t.end_attempt("a", ok=False)
        self.assertTrue(self.t.begin_attempt("a"))
        self.assertEqual(self.t.end_attempt("a", ok=True), 0.0)
        self.assertTrue(self.t.begin_attempt("a"))
        self.assertEqual(self.t.end_attempt("a", ok=False), 60.0)

    def test_old_failures_expire_by_window(self) -> None:
        for _ in range(3):
            self.t.failure("b")
        self.now[0] += 301  # окно истекло
        self.assertEqual(self.t.failure("b"), 0.0)
        self.assertEqual(self.t.failure("b"), 0.0)

    def test_attempts_in_flight_count_toward_the_limit(self) -> None:
        # Пять паролей проверяются одновременно — шестой ждать не должен.
        for _ in range(5):
            self.assertTrue(self.t.begin_attempt("c"))
        self.assertFalse(self.t.begin_attempt("c"))
        self.assertTrue(self.t.begin_attempt("d"), "другой адрес не затронут")
        blocks = [self.t.end_attempt("c", ok=False) for _ in range(5)]
        self.assertEqual(blocks[-1], 60.0)
        self.assertFalse(self.t.begin_attempt("c"), "заблокирован")

    def test_finished_successful_attempts_free_their_slot(self) -> None:
        for _ in range(20):
            self.assertTrue(self.t.begin_attempt("e"))
            self.t.end_attempt("e", ok=True)
        self.assertEqual(self.t._inflight.get("e", 0), 0)

    def test_pending_and_open_limits(self) -> None:
        t = AuthThrottle(max_pending=2, max_open=3)
        self.assertTrue(t.connection_opened("x") and t.connection_opened("x"))
        self.assertFalse(t.connection_opened("x"), "третье без входа")
        t.authenticated("x")
        self.assertTrue(t.connection_opened("x"), "после входа место освободилось")
        self.assertFalse(t.connection_opened("x"), "всего не больше max_open")
        t.connection_closed("x", authenticated=True)
        t.connection_closed("x", authenticated=False)
        t.connection_closed("x", authenticated=False)
        self.assertTrue(t.connection_opened("x"))
        self.assertTrue(t.connection_opened("other"))

    def test_tables_do_not_grow_forever(self) -> None:
        for i in range(500):
            for _ in range(5):
                self.t.failure(f"10.0.{i // 250}.{i % 250}")
        self.now[0] += 10_000
        self.t.failure("trigger")
        for _ in range(4):
            self.t.failure("trigger")
        self.assertLess(len(self.t._blocked_until), 10)
        self.assertLess(len(self.t._failures), 10)

    def test_failures_below_the_limit_are_pruned_too(self) -> None:
        # Много адресов, у каждого меньше пяти неудач, — блокировка не наступает,
        # но таблица всё равно не должна расти бесконечно.
        for i in range(1100):
            self.t.failure(f"10.1.{i // 250}.{i % 250}")
        self.now[0] += 301
        for i in range(30):
            self.t.failure(f"10.2.0.{i}")
        self.assertLess(len(self.t._failures), 1100)


# --- настоящий сервер -----------------------------------------------------------
class ServerTests(TempEnv):
    def setUp(self) -> None:
        super().setUp()
        patcher = mock.patch.object(share_server, "FAIL_DELAY", 0.0)
        patcher.start()
        self.addCleanup(patcher.stop)
        (self.root / "share").mkdir()
        self.now = [5000.0]
        self.throttle = AuthThrottle(clock=lambda: self.now[0], max_pending=3)
        self.key = asyncssh.generate_private_key("ssh-ed25519")
        pw_user = ShareUser(name="pw", read_only=True)
        pw_user.set_password(GOOD)
        cfg = ShareConfig(
            folder=str(self.root / "share"), port=0, bind="127.0.0.1",
            users=[pw_user, ShareUser(name="key", keys=[self.key.export_public_key().decode()])],
        )
        self.logs: list[str] = []
        self.server = ShareServer(cfg, log=lambda m, _l: self.logs.append(m), throttle=self.throttle)
        self.server.start()
        self.addCleanup(self.server.stop)

    def _password_login(self, password: str) -> str:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        try:
            client.connect("127.0.0.1", self.server.port, username="pw", password=password,
                           allow_agent=False, look_for_keys=False, timeout=5)
            return "ok"
        except paramiko.AuthenticationException:
            return "denied"
        except (paramiko.SSHException, EOFError, ConnectionError, OSError):
            return "dropped"
        finally:
            client.close()

    def test_password_login_works_through_scrypt(self) -> None:
        self.assertEqual(self._password_login(GOOD), "ok")
        self.assertEqual(self._password_login("wrong-password"), "denied")

    def test_brute_force_gets_the_address_blocked_then_released(self) -> None:
        results = [self._password_login(f"guess-{i}") for i in range(5)]
        self.assertNotIn("ok", results)
        self.assertGreater(self.throttle.blocked_for("127.0.0.1"), 0)
        # правильный пароль в блокировку не помогает
        self.assertEqual(self._password_login(GOOD), "dropped")
        self.assertTrue(any("заблокирован" in m for m in self.logs))
        self.now[0] += 61
        self.assertEqual(self._password_login(GOOD), "ok")

    def test_unknown_user_is_throttled_too(self) -> None:
        for i in range(5):
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            try:
                client.connect("127.0.0.1", self.server.port, username="nobody", password=f"x{i}",
                               allow_agent=False, look_for_keys=False, timeout=5)
            except Exception:  # noqa: BLE001
                pass
            finally:
                client.close()
        self.assertGreater(self.throttle.blocked_for("127.0.0.1"), 0)

    def test_failed_keys_do_not_lock_anyone_out(self) -> None:
        async def attempts() -> int:
            ok = 0
            for _ in range(8):
                try:
                    await asyncssh.connect("127.0.0.1", self.server.port, username="key",
                                           client_keys=[asyncssh.generate_private_key("ssh-ed25519")],
                                           known_hosts=None, password=None)
                except asyncssh.PermissionDenied:
                    pass
            conn = await asyncssh.connect("127.0.0.1", self.server.port, username="key",
                                          client_keys=[self.key], known_hosts=None)
            ok += 1
            conn.close()
            return ok

        self.assertEqual(asyncio.run(attempts()), 1)
        self.assertEqual(self.throttle.blocked_for("127.0.0.1"), 0)

    def test_connection_flood_without_login_is_capped_but_logged_in_clients_are_not(self) -> None:
        socks = []
        banners = []
        for _ in range(6):
            s = socket.create_connection(("127.0.0.1", self.server.port), timeout=2)
            socks.append(s)
            try:
                banners.append(s.recv(8))
            except OSError:
                banners.append(b"")
        self.assertEqual([b[:4] for b in banners[:3]], [b"SSH-"] * 3)
        self.assertTrue(all(b == b"" for b in banners[3:]), banners)
        for s in socks:
            s.close()

    def test_authenticated_connections_free_their_pending_slot(self) -> None:
        async def many() -> int:
            conns = []
            for _ in range(6):  # лимит «без входа» — 3, но вошедших может быть больше
                conns.append(await asyncssh.connect("127.0.0.1", self.server.port, username="key",
                                                    client_keys=[self.key], known_hosts=None))
            for c in conns:
                c.close()
            return len(conns)

        self.assertEqual(asyncio.run(many()), 6)

    def test_slots_are_released_when_clients_leave(self) -> None:
        for _ in range(10):
            s = socket.create_connection(("127.0.0.1", self.server.port), timeout=2)
            self.assertEqual(s.recv(4), b"SSH-")
            s.close()
            for _ in range(50):  # даём серверу заметить закрытие
                if not self.throttle._pending.get("127.0.0.1"):
                    break
                import time
                time.sleep(0.02)
        self.assertEqual(self.throttle._open.get("127.0.0.1", 0), 0)


# --- ключ сервера -----------------------------------------------------------------
class HostKeyFileTests(TempEnv):
    @unittest.skipIf(os.name == "nt", "на Windows права задаются через ACL")
    def test_key_file_is_owner_only_from_the_start(self) -> None:
        modes = []
        real_write = Path.write_bytes

        def spy(self_, data):
            modes.append(stat.S_IMODE(self_.stat().st_mode))  # права ДО записи ключа
            return real_write(self_, data)

        with mock.patch.object(Path, "write_bytes", spy):
            hostkey.load_or_create()
        self.assertEqual(modes, [0o600])

    @unittest.skipIf(os.name == "nt", "на Windows права задаются через ACL")
    def test_loose_legacy_file_is_tightened(self) -> None:
        key = hostkey.load_or_create()
        path = hostkey.paths.host_key_file()
        os.chmod(path, 0o644)
        again = hostkey.load_or_create()
        self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o600)
        self.assertEqual(hostkey.fingerprint(key), hostkey.fingerprint(again))


if __name__ == "__main__":
    unittest.main()
