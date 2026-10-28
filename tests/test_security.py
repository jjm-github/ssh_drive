"""Регрессионные тесты для исправлений безопасности.

Запуск (из корня проекта):  python -m unittest discover -s tests -v
Windows и сеть не нужны: DPAPI, subprocess и загрузки подменяются.
"""

from __future__ import annotations

import base64
import hashlib
import io
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
import zipfile
from pathlib import Path
from unittest import mock

import paramiko

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from sshdrive import keys, paths, profiles, rclone, secretstore, sshutil, winfsp  # noqa: E402

SECRET = "Sup3r-S3cret!"


class TempEnv(unittest.TestCase):
    """Каждому тесту — свои APPDATA / LOCALAPPDATA."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.root = Path(self._tmp.name)
        patcher = mock.patch.dict(
            os.environ,
            {"APPDATA": str(self.root / "roaming"), "LOCALAPPDATA": str(self.root / "local")},
        )
        patcher.start()
        self.addCleanup(patcher.stop)


# --- п. 1: ключ не попадает на диск ------------------------------------------
class KeyPemTests(TempEnv):
    def test_encrypted_key_goes_to_env_not_to_disk(self) -> None:
        key = self.root / "id_ed25519"
        keys.generate(key, "me@pc", "pass phrase")
        profile = profiles.Profile(host="h", user="u", auth="key", key_path=str(key))
        seen: dict = {}

        def fake_popen(args, env=None, **_kw):
            seen["env"] = env
            raise OSError("stop here")

        with mock.patch.object(rclone, "find_exe", return_value="rclone.exe"), \
                mock.patch.object(rclone, "drive_exists", return_value=False), \
                mock.patch.object(rclone, "supports_host_key_pinning", return_value=True), \
                mock.patch.object(subprocess, "Popen", fake_popen):
            with self.assertRaises(rclone.RcloneError):
                rclone.mount(profile, passphrase="pass phrase", drive="Z", host_key="ssh-ed25519 AAAA")

        env = seen["env"]
        self.assertNotIn("RCLONE_CONFIG_SSHDRIVE_KEY_FILE", env)
        pem = env["RCLONE_CONFIG_SSHDRIVE_KEY_PEM"]
        self.assertNotIn("\n", pem)
        self.assertTrue(pem.startswith("-----BEGIN OPENSSH PRIVATE KEY-----\\n"))
        self.assertTrue(pem.endswith("-----END OPENSSH PRIVATE KEY-----"))
        self.assertEqual(list(paths.tmp_dir().glob("*")) if paths.tmp_dir().exists() else [], [])

    def test_unencrypted_key_uses_file(self) -> None:
        key = self.root / "id_plain"
        keys.generate(key, "me@pc", "")
        profile = profiles.Profile(host="h", user="u", auth="key", key_path=str(key))
        seen: dict = {}

        def fake_popen(args, env=None, **_kw):
            seen["env"] = env
            raise OSError("stop here")

        with mock.patch.object(rclone, "find_exe", return_value="rclone.exe"), \
                mock.patch.object(rclone, "drive_exists", return_value=False), \
                mock.patch.object(subprocess, "Popen", fake_popen):
            with self.assertRaises(rclone.RcloneError):
                rclone.mount(profile, drive="Z")
        self.assertIn("RCLONE_CONFIG_SSHDRIVE_KEY_FILE", seen["env"])
        self.assertNotIn("RCLONE_CONFIG_SSHDRIVE_KEY_PEM", seen["env"])

    def test_stale_decrypted_keys_are_purged(self) -> None:
        paths.tmp_dir().mkdir(parents=True)
        stale = paths.tmp_dir() / "key-abc.pem"
        stale.write_text("PRIVATE")
        paths.ensure_dirs()
        self.assertFalse(stale.exists())


# --- п. 2: пароль не в командной строке ---------------------------------------
class ObscureTests(unittest.TestCase):
    def test_password_goes_through_stdin(self) -> None:
        calls = []

        def fake_run(args, **kw):
            calls.append((args, kw))
            return subprocess.CompletedProcess(args, 0, stdout="obscured\n", stderr="")

        with mock.patch.object(subprocess, "run", fake_run):
            self.assertEqual(rclone.obscure("rclone.exe", SECRET), "obscured")
        args, kw = calls[0]
        self.assertNotIn(SECRET, " ".join(args))
        self.assertEqual(kw["input"], SECRET + "\n")

    def test_timeout_message_has_no_secret(self) -> None:
        def fake_run(args, **kw):
            raise subprocess.TimeoutExpired(args, 30)

        with mock.patch.object(subprocess, "run", fake_run):
            with self.assertRaises(rclone.RcloneError) as ctx:
                rclone.obscure("rclone.exe", SECRET)
        self.assertNotIn(SECRET, str(ctx.exception))

    def test_newline_rejected(self) -> None:
        with self.assertRaises(rclone.RcloneError):
            rclone.obscure("rclone.exe", "a\nb")


# --- п. 3: установка WinFsp ----------------------------------------------------
class WinfspTests(TempEnv):
    def test_ps_quote_doubles_all_quote_kinds(self) -> None:
        self.assertEqual(winfsp._ps_quote("C:\\Users\\O'Brien"), "'C:\\Users\\O''Brien'")
        self.assertEqual(winfsp._ps_quote("a\u2019b"), "'a\u2019\u2019b'")

    def test_signature_check_fails_closed(self) -> None:
        with mock.patch.object(subprocess, "run", side_effect=OSError("no powershell")):
            with self.assertRaises(RuntimeError):
                winfsp._check_signature(Path("x.msi"), None)
        bad = subprocess.CompletedProcess([], 11, stdout="BAD signer CN=Evil\n", stderr="")
        with mock.patch.object(subprocess, "run", return_value=bad):
            with self.assertRaises(RuntimeError):
                winfsp._check_signature(Path("x.msi"), None)

    def test_install_runs_signature_check_inside_elevated_process(self) -> None:
        workdir = Path(tempfile.mkdtemp(prefix="sshdrive-winfsp-"))
        msi = workdir / "winfsp.msi"
        msi.write_bytes(b"msi")
        captured = {}

        def fake_run(args, **kw):
            captured["args"] = args
            return subprocess.CompletedProcess(args, winfsp.EXIT_BAD_SIGNER, stdout="", stderr="")

        with mock.patch.object(winfsp, "download", return_value=msi), \
                mock.patch.object(subprocess, "run", fake_run):
            with self.assertRaises(RuntimeError) as ctx:
                winfsp.install()
        self.assertIn("издателем", str(ctx.exception))
        self.assertFalse(workdir.exists(), "временный каталог должен быть удалён")

        def decode(args):
            return base64.b64decode(args[args.index("-EncodedCommand") + 1]).decode("utf-16-le")

        launcher = decode(captured["args"])
        self.assertIn("-Verb RunAs", launcher)
        inner_b64 = launcher.split("'-EncodedCommand', '")[1].split("'")[0]
        elevated = base64.b64decode(inner_b64).decode("utf-16-le")
        self.assertIn("Get-AuthenticodeSignature", elevated)
        self.assertIn("SystemRoot ('Temp", elevated)
        self.assertLess(elevated.index("Get-AuthenticodeSignature"), elevated.index("msiexec.exe"))
        for name in winfsp.EXPECTED_SIGNERS:
            self.assertIn(f"'{name}'", elevated)
        self.assertIn("OrdinalIgnoreCase", elevated)
        self.assertNotIn(".Contains(", elevated)  # регистрозависимо: Subject = «NAVIMATICS LLC»

    def test_precheck_script_matches_signer_case_insensitively(self) -> None:
        seen = {}

        def fake_run(args, **kw):
            seen["script"] = base64.b64decode(args[args.index("-EncodedCommand") + 1]).decode("utf-16-le")
            return subprocess.CompletedProcess(args, 0, stdout="OK CN=NAVIMATICS LLC\n", stderr="")

        with mock.patch.object(subprocess, "run", fake_run):
            winfsp._check_signature(Path("x.msi"), None)
        self.assertIn("OrdinalIgnoreCase", seen["script"])
        self.assertNotIn(".Contains(", seen["script"])

    def test_expected_signer_matches_real_subject(self) -> None:
        subject = "CN=NAVIMATICS LLC, O=NAVIMATICS LLC, L=KIRKLAND, S=Washington, C=US"
        self.assertTrue(any(n.lower() in subject.lower() for n in winfsp.EXPECTED_SIGNERS))


class BundledMsiTests(TempEnv):
    """offline-сборка: MSI лежит рядом с exe, а не в нашем временном каталоге."""

    def _bundled(self) -> Path:
        folder = self.root / "bundle"
        folder.mkdir()
        msi = folder / "winfsp-2.1.msi"
        msi.write_bytes(b"msi")
        (folder / "app.py").write_text("keep me")
        return msi

    def test_bundled_msi_is_signature_checked(self) -> None:
        msi = self._bundled()
        with mock.patch.object(paths, "bundled_glob", return_value=[msi]), \
                mock.patch.object(winfsp, "_check_signature") as check:
            self.assertEqual(winfsp.download(), msi)
        check.assert_called_once()

    def test_install_never_deletes_bundle_directory(self) -> None:
        msi = self._bundled()
        fake = subprocess.CompletedProcess([], 0, stdout="", stderr="")
        with mock.patch.object(winfsp, "download", return_value=msi), \
                mock.patch.object(subprocess, "run", return_value=fake), \
                mock.patch.object(winfsp, "is_installed", return_value=True):
            winfsp.install()
        self.assertTrue(msi.exists())
        self.assertTrue((msi.parent / "app.py").exists())

    def test_cleanup_removes_only_own_download_dirs(self) -> None:
        own = Path(tempfile.mkdtemp(prefix="sshdrive-winfsp-"))
        (own / "x.msi").write_bytes(b"1")
        winfsp.cleanup_download(own / "x.msi")
        self.assertFalse(own.exists())
        stranger = self.root / "sshdrive-winfsp-lookalike"
        stranger.mkdir()
        (stranger / "x.msi").write_bytes(b"1")
        winfsp.cleanup_download(stranger / "x.msi")
        self.assertTrue(stranger.exists())

    def test_find_exe_prefers_bundled_over_path(self) -> None:
        bundled = self.root / "rclone.exe"
        bundled.write_text("x")
        with mock.patch.dict(os.environ, {"PATH": "", "SSHDRIVE_RCLONE": ""}), \
                mock.patch.object(rclone, "PINNED_EXE_SHA256", hashlib.sha256(b"x").hexdigest()), \
                mock.patch.object(paths, "install_dir", return_value=self.root / "nowhere"), \
                mock.patch.object(paths, "bundled_file", return_value=bundled):
            self.assertEqual(rclone.find_exe(), str(bundled))


# --- п. 4: загрузка rclone -----------------------------------------------------
class DownloadTests(TempEnv):
    def _zip(self, member: str = "rclone-v1/rclone.exe") -> bytes:
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as zf:
            zf.writestr(member, b"MZ-fake-rclone")
        return buf.getvalue()

    def test_hash_mismatch_installs_nothing(self) -> None:
        blob = self._zip()
        with mock.patch.object(rclone, "_fetch", lambda url, dest, progress=None: dest.write_bytes(blob)):
            with self.assertRaises(rclone.RcloneError):
                rclone.download_executable()
        self.assertFalse(paths.rclone_exe().exists())

    def test_matching_hash_installs(self) -> None:
        blob = self._zip()
        digest = hashlib.sha256(blob).hexdigest()
        exe_digest = hashlib.sha256(b"MZ-fake-rclone").hexdigest()
        with mock.patch.object(rclone, "PINNED_SHA256", digest), \
                mock.patch.object(rclone, "PINNED_EXE_SHA256", exe_digest), \
                mock.patch.object(rclone, "_fetch", lambda url, dest, progress=None: dest.write_bytes(blob)):
            exe = rclone.download_executable()
        self.assertEqual(Path(exe).read_bytes(), b"MZ-fake-rclone")

    def test_member_must_be_exactly_rclone_exe(self) -> None:
        blob = self._zip("evil-rclone.exe")
        digest = hashlib.sha256(blob).hexdigest()
        with mock.patch.object(rclone, "PINNED_SHA256", digest), \
                mock.patch.object(rclone, "_fetch", lambda url, dest, progress=None: dest.write_bytes(blob)):
            with self.assertRaises(rclone.RcloneError):
                rclone.download_executable()

    def test_pinned_hash_looks_sane(self) -> None:
        self.assertRegex(rclone.PINNED_SHA256, r"^[0-9a-f]{64}$")


# --- п. 5: публичный ключ -------------------------------------------------------
class PublicKeyTests(TempEnv):
    def test_forged_pub_file_is_ignored(self) -> None:
        key = self.root / "id_ed25519"
        keys.generate(key, "me@pc")
        real = (self.root / "id_ed25519.pub").read_text().split()[1]
        (self.root / "id_ed25519.pub").write_text(
            "ssh-ed25519 AAAAattacker evil\ncommand=\"/bin/sh\" ssh-ed25519 AAAAattacker2 evil\n"
        )
        line = keys.public_line(key)
        self.assertEqual(line, f"ssh-ed25519 {real}")
        self.assertEqual(len(line.splitlines()), 1)

    def test_matching_pub_comment_kept_but_sanitised(self) -> None:
        key = self.root / "id_ed25519"
        keys.generate(key, "me@pc")
        blob = (self.root / "id_ed25519.pub").read_text().split()[1]
        (self.root / "id_ed25519.pub").write_text(f"ssh-ed25519 {blob} we ird'; calc\n")
        self.assertEqual(keys.public_line(key), f"ssh-ed25519 {blob} we_ird___calc")

    def test_validate_public_key(self) -> None:
        good = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc me@pc"
        self.assertEqual(sshutil.validate_public_key(good + "\n"), good)
        for bad in (
            good + "\nssh-rsa AAAA x",
            "command=\"x\" " + good,
            "ssh-ed25519 AAAA x'; calc.exe; '",
            "ssh-ed25519 AAAA x\u2019; calc.exe; \u2019",
            "ssh-ed25519 AAAA $(id)",
            "",
        ):
            with self.assertRaises(sshutil.SSHError, msg=repr(bad)):
                sshutil.validate_public_key(bad)


# --- п. 6: Windows-сервер -------------------------------------------------------
class WindowsScriptTests(unittest.TestCase):
    KEY = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIabc me@pc"

    def test_admin_file_is_opt_in(self) -> None:
        self.assertIn("$writeAdmin = $false", sshutil._windows_install_script(self.KEY))
        self.assertIn("$writeAdmin = $true", sshutil._windows_install_script(self.KEY, True))

    def test_if_condition_is_parenthesised(self) -> None:
        script = sshutil._windows_install_script(self.KEY)
        self.assertIn("if ($isAdmin -and ($file -like '*administrators_authorized_keys'))", script)
        # скобки и фигурные скобки сбалансированы
        for a, b in ("()", "{}"):
            self.assertEqual(script.count(a), script.count(b), (a, b))

    def test_admin_file_untouched_without_consent(self) -> None:
        scripts = []

        def fake_run(client, command, timeout=30.0):
            if command.startswith("umask"):
                return 1, "", "not posix"
            scripts.append(base64.b64decode(command.split("-EncodedCommand ")[1]).decode("utf-16-le"))
            return 0, "SSHDRIVE_ADMIN_SESSION\nupdated: C:\\u\\.ssh\\authorized_keys\nSSHDRIVE_OK\n", ""

        with mock.patch.object(sshutil, "run", fake_run):
            result = sshutil.install_public_key(object(), self.KEY, confirm_admin=lambda: False)
            self.assertEqual(len(scripts), 1)
            self.assertIn("administrators_authorized_keys не изменён", result)
            sshutil.install_public_key(object(), self.KEY, confirm_admin=lambda: True)
            self.assertEqual(len(scripts), 3)
            self.assertIn("$writeAdmin = $true", scripts[-1])

    def test_unsafe_key_never_reaches_server(self) -> None:
        with mock.patch.object(sshutil, "run", side_effect=AssertionError("must not run")):
            with self.assertRaises(sshutil.SSHError):
                sshutil.install_public_key(object(), self.KEY + "\nssh-rsa AAAA evil")


# --- п. 7: поиск rclone ---------------------------------------------------------
class WhichTests(TempEnv):
    def test_skips_cwd_and_relative_entries(self) -> None:
        name = "rclone.exe" if os.name == "nt" else "rclone"
        cwd_dir = self.root / "cwd"
        good_dir = self.root / "good"
        for d in (cwd_dir, good_dir):
            d.mkdir()
            (d / name).write_text("x")
        old = Path.cwd()
        os.chdir(cwd_dir)
        self.addCleanup(os.chdir, old)
        with mock.patch.dict(os.environ, {"PATH": os.pathsep.join(["", ".", str(cwd_dir), str(good_dir)])}):
            self.assertEqual(rclone._which_safe(), str(good_dir / name))

    def test_system_exe_is_absolute(self) -> None:
        with mock.patch.dict(os.environ, {"SystemRoot": r"C:\Windows"}):
            self.assertTrue(paths.system_exe("net.exe").lower().endswith("net.exe"))
            self.assertIn("System32", paths.powershell_exe())


# --- п. 9: DPAPI ------------------------------------------------------------------
class SecretStoreTests(unittest.TestCase):
    def setUp(self) -> None:
        self.entropies: list = []

        def fake_protect(data, entropy):
            self.entropies.append(entropy)
            return b"E:" + data

        def fake_unprotect(raw, entropy):
            self.entropies.append(entropy)
            return raw[2:]

        for name, func in (("_dpapi_protect", fake_protect), ("_dpapi_unprotect", fake_unprotect)):
            patcher = mock.patch.object(secretstore, name, func)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_new_tokens_use_entropy_and_prefix(self) -> None:
        token = secretstore.protect(SECRET)
        self.assertTrue(token.startswith("v2:"))
        self.assertEqual(secretstore.unprotect(token), SECRET)
        self.assertEqual(self.entropies, [secretstore._ENTROPY, secretstore._ENTROPY])

    def test_legacy_tokens_still_readable_without_entropy(self) -> None:
        legacy = base64.b64encode(b"E:" + SECRET.encode()).decode()
        self.assertEqual(secretstore.unprotect(legacy), SECRET)
        self.assertEqual(self.entropies, [None])

    def test_empty(self) -> None:
        self.assertEqual(secretstore.protect(""), "")
        self.assertEqual(secretstore.unprotect(""), "")


# --- п. 10: опции rclone и id ------------------------------------------------------
class ExtraOptsTests(unittest.TestCase):
    def test_allowed(self) -> None:
        self.assertEqual(
            rclone.validate_extra("--vfs-cache-max-size 4G --transfers=4 --read-only"),
            ["--vfs-cache-max-size", "4G", "--transfers=4", "--read-only"],
        )
        self.assertEqual(rclone.validate_extra(""), [])

    def test_dangerous_flags_rejected(self) -> None:
        for extra in (
            '--sftp-ssh "cmd /c calc.exe"',
            "--rc --rc-addr :5572 --rc-no-auth",
            "--config C:/evil.conf",
            "--sftp-pass abc",
            "--sftp-key-file C:/x",
            "--sftp-known-hosts-file C:/x",
            "--sftp-host evil.example",
            "-o x",
            "--transfers 4 --password-command calc",
            "---transfers 4",
        ):
            with self.assertRaises(rclone.RcloneError, msg=extra):
                rclone.validate_extra(extra)


class RcloneOutputTests(unittest.TestCase):
    def test_root_readlink_probe_is_hidden(self) -> None:
        line = "2026/10/28 20:33:55 ERROR : symlinks not supported without the --links flag: /"
        self.assertTrue(rclone.is_benign_line(line))

    def test_other_paths_and_errors_are_kept(self) -> None:
        for line in (
            "2026/10/28 20:33:55 ERROR : symlinks not supported without the --links flag: /docs/link",
            "2026/10/28 20:33:55 ERROR : symlinks not supported without the --links flag: /x/",
            "2026/10/28 20:33:55 Failed to mount: access denied",
            "2026/10/28 20:33:55 NOTICE: sftp: handshake failed",
        ):
            self.assertFalse(rclone.is_benign_line(line), line)

    def test_reader_drops_probe_but_keeps_real_output(self) -> None:
        probe = "2026/10/28 20:33:55 ERROR : symlinks not supported without the --links flag: /"
        lines = [probe + "\n", "The service rclone has been started.\n"]
        proc = mock.Mock()
        proc.stdout = iter(lines)
        proc.poll.return_value = None
        seen: list[str] = []
        with mock.patch.object(rclone, "find_exe", return_value="rclone.exe"), \
                mock.patch.object(rclone, "drive_exists", return_value=True), \
                mock.patch.object(subprocess, "Popen", return_value=proc), \
                tempfile.TemporaryDirectory() as tmp, \
                mock.patch.dict(os.environ, {"APPDATA": tmp, "LOCALAPPDATA": tmp}):
            profile = profiles.Profile(host="h", user="u", auth="password")
            with mock.patch.object(rclone, "obscure", return_value="x"), \
                    mock.patch.object(rclone, "drive_exists", side_effect=[False, True]):
                handle = rclone.mount(profile, password="p", drive="Z", on_line=seen.append)
            deadline = time.monotonic() + 2
            while len(seen) < 1 and time.monotonic() < deadline:
                time.sleep(0.01)
        self.assertEqual(seen, ["The service rclone has been started."])
        self.assertEqual(handle.output, ["The service rclone has been started."])


class ProfileIdTests(unittest.TestCase):
    def test_bad_id_is_replaced(self) -> None:
        for bad in ("..\\..\\evil", "a/b", "", "x" * 64, 5):
            self.assertRegex(profiles.Profile(id=bad).id, r"^[0-9a-f]{12}$")
        self.assertEqual(profiles.Profile(id="abc123DEF-_").id, "abc123DEF-_")


    def test_drive_letters_are_sanitised(self) -> None:
        profile = profiles.Profile(drive="z", last_drive="-")
        self.assertEqual((profile.drive, profile.last_drive), ("Z", ""))
        self.assertEqual(profiles.Profile(drive="\u0416", last_drive="1").drive, "")


class KeyAclTests(TempEnv):
    @unittest.skipIf(os.name == "nt", "на Windows права задаются через ACL")
    def test_private_key_is_owner_only(self) -> None:
        key = self.root / "id_ed25519"
        keys.generate(key, "me@pc")
        self.assertEqual(key.stat().st_mode & 0o777, 0o600)


# --- проверка ключа хоста (регрессия после удаления мёртвой ветки) ----------------
class HostKeyTests(TempEnv):
    HOST, PORT = "127.0.0.1", 0

    class _Server(paramiko.ServerInterface):
        def check_auth_password(self, username, password):
            return paramiko.AUTH_SUCCESSFUL

        def get_allowed_auths(self, username):
            return "password"

    def _serve(self, host_key):
        sock = socket.socket()
        sock.bind((self.HOST, 0))
        sock.listen(1)
        port = sock.getsockname()[1]

        def run():
            conn, _ = sock.accept()
            t = paramiko.Transport(conn)
            t.add_server_key(host_key)
            try:
                t.start_server(server=self._Server())
                t.accept(5)
            except Exception:  # noqa: BLE001 - клиент мог оборвать рукопожатие
                pass
            finally:
                t.close()
                sock.close()

        threading.Thread(target=run, daemon=True).start()
        return port

    def test_new_host_asks_with_three_args_and_saves_key(self) -> None:
        key = paramiko.RSAKey.generate(2048)
        port = self._serve(key)
        known = self.root / "known_hosts"
        asked = []

        def confirm(host, keytype, fp):
            asked.append((host, keytype, fp))
            return True

        client = sshutil.connect(self.HOST, port, "u", password="p", known_hosts=known, confirm=confirm)
        client.close()
        self.assertEqual(len(asked), 1)
        self.assertIn("ssh-rsa", known.read_text())

    def test_changed_key_is_blocked_even_for_other_type(self) -> None:
        known = self.root / "known_hosts"
        trusted = paramiko.Ed25519Key.from_private_key(
            io.StringIO(_ed25519_pem())
        )
        hosts = paramiko.HostKeys()
        port = self._serve(paramiko.RSAKey.generate(2048))
        hosts.add(f"[{self.HOST}]:{port}", trusted.get_name(), trusted)
        hosts.save(str(known))
        before = known.read_text()
        with self.assertRaises(sshutil.HostKeyMismatch):
            sshutil.connect(
                self.HOST, port, "u", password="p", known_hosts=known,
                confirm=lambda *_a: self.fail("не должны спрашивать"),
            )
        self.assertEqual(known.read_text(), before)


def _ed25519_pem() -> str:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ed25519

    return ed25519.Ed25519PrivateKey.generate().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.OpenSSH,
        serialization.NoEncryption(),
    ).decode()


if __name__ == "__main__":
    unittest.main()
