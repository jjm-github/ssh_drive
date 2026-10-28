"""Шифрование паролей через DPAPI (текущий пользователь Windows).

Пароли никогда не пишутся в открытом виде: в profiles.json лежит только
base64-строка, зашифрованная CryptProtectData. Расшифровать её может учётная
запись Windows, под которой она создана (в домене с перемещаемым профилем —
и на других компьютерах этой учётной записи).

DPAPI не защищает от других программ, запущенных тем же пользователем: они
тоже могут вызвать CryptUnprotectData. Дополнительная «энтропия» (v2) лишь
отсекает универсальные утилиты, которые расшифровывают DPAPI-блоки без
знания приложения.
"""

from __future__ import annotations

import base64
import ctypes
import os
from ctypes import wintypes

CRYPTPROTECT_UI_FORBIDDEN = 0x1
V2_PREFIX = "v2:"
_ENTROPY = b"SSHDrive/profiles/v2"


class _DataBlob(ctypes.Structure):
    _fields_ = [
        ("cbData", wintypes.DWORD),
        ("pbData", ctypes.POINTER(ctypes.c_byte)),
    ]


if os.name == "nt":
    _crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _crypt32.CryptProtectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        wintypes.LPCWSTR,
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptProtectData.restype = wintypes.BOOL

    _crypt32.CryptUnprotectData.argtypes = [
        ctypes.POINTER(_DataBlob),
        ctypes.POINTER(wintypes.LPWSTR),
        ctypes.POINTER(_DataBlob),
        ctypes.c_void_p,
        ctypes.c_void_p,
        wintypes.DWORD,
        ctypes.POINTER(_DataBlob),
    ]
    _crypt32.CryptUnprotectData.restype = wintypes.BOOL

    _kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    _kernel32.LocalFree.restype = ctypes.c_void_p
else:  # pragma: no cover - приложение всё же под Windows
    _crypt32 = None
    _kernel32 = None


def _make_blob(data: bytes) -> tuple[_DataBlob, object]:
    buf = ctypes.create_string_buffer(data, len(data))
    blob = _DataBlob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_byte)))
    return blob, buf


def _take_blob(blob: _DataBlob) -> bytes:
    try:
        return ctypes.string_at(blob.pbData, blob.cbData)
    finally:
        if blob.pbData:
            _kernel32.LocalFree(ctypes.cast(blob.pbData, ctypes.c_void_p))


def _dpapi_protect(data: bytes, entropy: bytes | None) -> bytes:
    if _crypt32 is None:
        raise RuntimeError("DPAPI доступен только на Windows")
    in_blob, _keep = _make_blob(data)
    ent_blob, _keep_ent = _make_blob(entropy) if entropy else (None, None)
    out_blob = _DataBlob()
    ok = _crypt32.CryptProtectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob) if ent_blob is not None else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return _take_blob(out_blob)


def _dpapi_unprotect(raw: bytes, entropy: bytes | None) -> bytes:
    if _crypt32 is None:
        raise RuntimeError("DPAPI доступен только на Windows")
    in_blob, _keep = _make_blob(raw)
    ent_blob, _keep_ent = _make_blob(entropy) if entropy else (None, None)
    out_blob = _DataBlob()
    ok = _crypt32.CryptUnprotectData(
        ctypes.byref(in_blob),
        None,
        ctypes.byref(ent_blob) if ent_blob is not None else None,
        None,
        None,
        CRYPTPROTECT_UI_FORBIDDEN,
        ctypes.byref(out_blob),
    )
    if not ok:
        raise ctypes.WinError(ctypes.get_last_error())
    return _take_blob(out_blob)


def protect(text: str) -> str:
    """Шифрует строку и возвращает «v2:» + base64."""
    if not text:
        return ""
    encrypted = _dpapi_protect(text.encode("utf-8"), _ENTROPY)
    return V2_PREFIX + base64.b64encode(encrypted).decode("ascii")


def unprotect(token: str) -> str:
    """Расшифровывает строку, созданную protect().

    Записи без префикса — прошлых версий (без энтропии) — читаются как раньше.
    """
    if not token:
        return ""
    if token.startswith(V2_PREFIX):
        raw = base64.b64decode(token[len(V2_PREFIX):])
        return _dpapi_unprotect(raw, _ENTROPY).decode("utf-8")
    return _dpapi_unprotect(base64.b64decode(token), None).decode("utf-8")


def try_unprotect(token: str) -> str | None:
    """Как unprotect(), но возвращает None вместо исключения."""
    try:
        return unprotect(token)
    except Exception:
        return None
