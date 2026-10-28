"""Графический интерфейс SSH Drive (tkinter — самый лёгкий вариант, входит в Python)."""

from __future__ import annotations

import os
import queue
import sys
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import messagebox, ttk

from . import autostart, keys, paths, rclone, sshutil, winfsp
from .dialogs import KnownHostsDialog, ProfileDialog, ask_secret
from .profiles import Profile, ProfileStore
from .secretstore import protect, try_unprotect
from .tray import TrayIcon, make_icon_image

LEVEL_COLORS = {
    "info": "#202020",
    "ok": "#1a7f37",
    "warn": "#9a6700",
    "err": "#b42318",
    "dim": "#6e7781",
}


class App(tk.Tk):
    def __init__(self, smoke: bool = False, start_hidden: bool = False) -> None:
        super().__init__()
        paths.ensure_dirs()
        self.smoke = smoke
        self.start_hidden = start_hidden
        self.store = ProfileStore()
        self.mounts: dict[str, rclone.MountHandle] = {}
        self.states: dict[str, str] = {}
        self.pending: set[str] = set()
        self.pending_drives: dict[str, str] = {}
        self.reserved: set[str] = set()
        self._autoconnect_done = False
        self._autoconnect_pending = False
        self._queue: queue.Queue = queue.Queue()
        self._log_lock = threading.Lock()
        self._asked_rclone = False
        self._asked_winfsp = False
        self._quitting = False
        self._tray_hint_shown = False
        self.tray: TrayIcon | None = None
        self.tray_ok = False
        self.autostart_var = tk.BooleanVar(value=autostart.is_enabled())

        self.title("SSH Drive — SSH-папка как диск Windows")
        self.geometry("1020x660")
        self.minsize(880, 560)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._set_window_icon()

        self.style = ttk.Style(self)
        for theme in ("vista", "winnative", "clam"):
            if theme in self.style.theme_names():
                self.style.theme_use(theme)
                break
        self.style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        self.style.configure("Treeview", rowheight=24)

        self._build_menu()
        self._build_ui()
        self._refresh_tree()
        self._drain_id = self.after(100, self._drain)
        self.log(f"Данные приложения: {paths.appdata_dir()}")
        self.after(200, self._init_tray)
        self.after(250, lambda: self._startup_checks(auto=True))

    # ------------------------------------------------------------------
    # Иконка в трее
    # ------------------------------------------------------------------
    def _set_window_icon(self) -> None:
        try:
            from PIL import ImageTk

            self._icon_photo = ImageTk.PhotoImage(make_icon_image(64))
            self.iconphoto(True, self._icon_photo)
        except Exception:  # noqa: BLE001 - иконка не критична
            self._icon_photo = None

    def _init_tray(self) -> None:
        if self.smoke or os.environ.get("SSHDRIVE_NO_TRAY") == "1":
            return
        tray = TrayIcon(
            on_open=lambda: self.ui(self._restore_window),
            on_disconnect_all=lambda: self.ui(self._disconnect_all),
            on_quit=lambda: self.ui(self._quit),
        )
        if not tray.available:
            self.log(f"Иконка в трее недоступна: {tray.error}", "warn")
            return
        self.tray = tray
        self.tray_ok = tray.start()
        if self.tray_ok:
            self.tray.set_tooltip("SSH Drive — дисков: 0")
            self.log("Иконка в трее активна: закрытие окна сворачивает программу", "dim")
            if self.start_hidden:
                self.withdraw()
                self.tray.notify("SSH Drive запущен в трее. Диски подключаются автоматически.")
                self.log("Запуск свёрнутым в трей (--tray)", "dim")
        else:
            self.log(f"Не удалось показать иконку в трее: {tray.error or 'неизвестная ошибка'}", "warn")

    def _toggle_autostart(self) -> None:
        want = bool(self.autostart_var.get())
        try:
            if want:
                autostart.enable()
            else:
                autostart.disable()
        except Exception as exc:  # noqa: BLE001 - показываем пользователю
            self.autostart_var.set(not want)
            self.log(f"Автозапуск: {exc}", "err")
            messagebox.showerror("Автозапуск", f"Не удалось изменить автозапуск:\n{exc}")
            return
        if want:
            self.log("Автозапуск при входе в Windows включён (запуск в трее)", "ok")
        else:
            self.log("Автозапуск при входе в Windows выключен")

    def hide_to_tray(self) -> None:
        if not self.tray_ok:
            self._quit()
            return
        self.withdraw()
        if not self._tray_hint_shown:
            self._tray_hint_shown = True
            if self.tray is not None:
                self.tray.notify("Программа свёрнута в трей. Диски остаются подключёнными.")
        self.log("Окно свёрнуто в трей (двойной клик по иконке — открыть)", "dim")

    def _restore_window(self) -> None:
        try:
            self.deiconify()
            self.lift()
            self.focus_force()
        except tk.TclError:
            pass

    # ------------------------------------------------------------------
    # Логирование и обмен с фоновыми потоками
    # ------------------------------------------------------------------
    def log(self, message: str, level: str = "info") -> None:
        stamp = time.strftime("%H:%M:%S")
        self._queue.put(("log", f"[{stamp}] {message}", level))
        try:
            with self._log_lock:
                with paths.app_log_file().open("a", encoding="utf-8") as handle:
                    handle.write(
                        f"{time.strftime('%Y-%m-%d %H:%M:%S')} {level.upper():4} {message}\n"
                    )
        except OSError:
            pass

    def ui(self, func, *args) -> None:
        self._queue.put(("ui", func, args))

    def run_bg(self, label: str, work) -> None:
        def runner() -> None:
            try:
                work()
            except (sshutil.AuthCancelled, InterruptedError):
                self.log(f"{label}: отменено", "warn")
            except Exception as exc:  # noqa: BLE001 - показываем пользователю
                self.log(f"{label}: {type(exc).__name__}: {exc}", "err")
                if os.environ.get("SSHDRIVE_DEBUG"):
                    self.log(traceback.format_exc(), "dim")

        threading.Thread(target=runner, name=label, daemon=True).start()

    def _drain(self) -> None:
        try:
            while True:
                kind, payload, extra = self._queue.get_nowait()
                if kind == "log":
                    self._append_log(payload, extra)
                elif kind == "ui":
                    try:
                        payload(*extra)
                    except Exception:  # noqa: BLE001
                        self._append_log(traceback.format_exc(), "err")
        except queue.Empty:
            pass
        self._drain_id = self.after(100, self._drain)

    def _append_log(self, text: str, level: str) -> None:
        self.log_text.configure(state="normal")
        self.log_text.insert("end", text + "\n", level)
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _progress(self, done: int, total: int) -> None:
        if total:
            percent = int(done * 100 / total)
            self.ui(self.env_var.set, f"Скачивание… {percent}%  ({done // (1024 * 1024)} МБ)")

    # ------------------------------------------------------------------
    # Интерфейс
    # ------------------------------------------------------------------
    def _build_menu(self) -> None:
        menu = tk.Menu(self)

        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Обновить список", command=self._refresh_tree)
        file_menu.add_separator()
        file_menu.add_command(label="Свернуть в трей", command=self.hide_to_tray)
        file_menu.add_command(label="Выход", command=self._quit)
        menu.add_cascade(label="Файл", menu=file_menu)

        tools = tk.Menu(menu, tearoff=False)
        tools.add_command(label="Проверить окружение", command=self._check_environment)
        tools.add_command(label="Скачать / обновить rclone", command=self._download_rclone)
        tools.add_command(label="Установить WinFsp", command=self._install_winfsp)
        tools.add_separator()
        tools.add_checkbutton(
            label="Запускать при входе в Windows",
            variable=self.autostart_var,
            command=self._toggle_autostart,
        )
        tools.add_separator()
        tools.add_command(label="Известные хосты…", command=self._show_known_hosts)
        tools.add_command(label="Открыть папку данных", command=self._open_data_dir)
        tools.add_command(label="Очистить журнал", command=self._clear_log)
        menu.add_cascade(label="Сервис", menu=tools)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="README", command=self._open_readme)
        help_menu.add_command(label="О программе", command=self._about)
        menu.add_cascade(label="Справка", menu=help_menu)

        self.configure(menu=menu)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=(12, 10, 12, 6))
        outer.pack(fill="both", expand=True)

        toolbar = ttk.Frame(outer)
        toolbar.pack(fill="x", pady=(0, 8))
        self.btn_add = ttk.Button(toolbar, text="Добавить", command=self._add_profile)
        self.btn_edit = ttk.Button(toolbar, text="Изменить", command=self._edit_profile)
        self.btn_delete = ttk.Button(toolbar, text="Удалить", command=self._delete_profile)
        self.btn_connect = ttk.Button(
            toolbar, text="Подключить", command=self._connect_selected, style="Accent.TButton"
        )
        self.btn_disconnect = ttk.Button(
            toolbar, text="Отключить", command=self._disconnect_selected
        )
        self.btn_test = ttk.Button(toolbar, text="Проверить вход", command=self._test_selected)
        self.btn_install_key = ttk.Button(
            toolbar, text="Установить ключ", command=self._install_key_selected
        )
        for button in (
            self.btn_add,
            self.btn_edit,
            self.btn_delete,
        ):
            button.pack(side="left", padx=(0, 6))
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=8)
        for button in (self.btn_connect, self.btn_disconnect, self.btn_test, self.btn_install_key):
            button.pack(side="left", padx=(0, 6))

        paned = ttk.Panedwindow(outer, orient="vertical")
        paned.pack(fill="both", expand=True)

        columns = ("name", "target", "auth", "drive", "state")
        tree_frame = ttk.Frame(paned)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", selectmode="browse")
        headings = {
            "name": ("Название", 220, "w"),
            "target": ("Сервер", 260, "w"),
            "auth": ("Вход", 80, "center"),
            "drive": ("Диск", 70, "center"),
            "state": ("Состояние", 240, "w"),
        }
        for column, (text, width, anchor) in headings.items():
            self.tree.heading(column, text=text)
            self.tree.column(column, width=width, anchor=anchor)
        self.tree.tag_configure("connected", foreground="#1a7f37")
        self.tree.tag_configure("error", foreground="#b42318")
        scroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<Double-1>", lambda _e: self._edit_profile())
        self.tree.bind("<Return>", lambda _e: self._connect_selected())
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._update_buttons())
        paned.add(tree_frame, weight=3)

        log_frame = ttk.LabelFrame(paned, text="Журнал", padding=6)
        self.log_text = tk.Text(
            log_frame,
            height=10,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            background="#fbfbfd",
            relief="flat",
        )
        for level, color in LEVEL_COLORS.items():
            self.log_text.tag_configure(level, foreground=color)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=log_scroll.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        log_scroll.pack(side="right", fill="y")
        paned.add(log_frame, weight=1)

        status = ttk.Frame(self, padding=(12, 0, 12, 8))
        status.pack(fill="x")
        self.env_var = tk.StringVar(value="Проверяю окружение…")
        ttk.Label(status, textvariable=self.env_var, foreground="#555555").pack(side="left")
        self.count_var = tk.StringVar(value="")
        ttk.Label(status, textvariable=self.count_var, foreground="#555555").pack(side="right")

        self._update_buttons()

    # ------------------------------------------------------------------
    # Таблица профилей
    # ------------------------------------------------------------------
    def _refresh_tree(self, select: str | None = None) -> None:
        current = select or self._selected_id()
        self.tree.delete(*self.tree.get_children())
        for profile in self.store.profiles:
            handle = self.mounts.get(profile.id)
            if handle and handle.alive:
                state = f"подключено ({handle.drive}:)"
                tags = ("connected",)
                drive = handle.drive
            else:
                state = self.states.get(profile.id, "")
                tags = ("error",) if state.startswith("ошибка") else ()
                drive = profile.drive
            self.tree.insert(
                "",
                "end",
                iid=profile.id,
                values=(
                    profile.title,
                    profile.target,
                    profile.auth_label,
                    f"{drive}:" if drive else "авто",
                    state,
                ),
                tags=tags,
            )
        # удаляем устаревшие состояния
        self.states = {k: v for k, v in self.states.items() if self.store.get(k)}
        if current and self.tree.exists(current):
            self.tree.selection_set(current)
            self.tree.focus(current)
        self._update_buttons()

    def _selected_id(self) -> str | None:
        selection = self.tree.selection()
        return selection[0] if selection else None

    def _selected_profile(self) -> Profile | None:
        profile_id = self._selected_id()
        return self.store.get(profile_id) if profile_id else None

    def _update_buttons(self) -> None:
        profile = self._selected_profile()
        has = profile is not None
        for button in (self.btn_edit, self.btn_delete, self.btn_connect, self.btn_test):
            button.configure(state="normal" if has else "disabled")
        if has and profile.id in self.pending:
            self.btn_connect.configure(state="disabled")
        connected = bool(profile and profile.id in self.mounts and self.mounts[profile.id].alive)
        self.btn_disconnect.configure(state="normal" if connected else "disabled")
        self.btn_install_key.configure(
            state="normal" if has and profile.auth in ("key", "agent") else "disabled"
        )
        connected_count = sum(1 for m in self.mounts.values() if m.alive)
        self.count_var.set(f"Дисков подключено: {connected_count}")
        if self.tray_ok and self.tray is not None:
            self.tray.set_tooltip(f"SSH Drive — дисков: {connected_count}")

    # ------------------------------------------------------------------
    # Профили
    # ------------------------------------------------------------------
    def _add_profile(self) -> None:
        profile = Profile()
        dialog = ProfileDialog(self, profile)
        self.wait_window(dialog)
        if dialog.result:
            self.store.add(dialog.result)
            self._refresh_tree(dialog.result.id)
            self.log(f"Профиль «{dialog.result.title}» создан")

    def _edit_profile(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            return
        if profile.id in self.pending:
            messagebox.showinfo("Профиль", "Профиль сейчас подключается — подождите.")
            return
        if profile.id in self.mounts and self.mounts[profile.id].alive:
            messagebox.showinfo(
                "Профиль", "Сначала отключите диск — настройки активного профиля менять нельзя."
            )
            return
        dialog = ProfileDialog(self, profile)
        self.wait_window(dialog)
        if dialog.result:
            self.store.update(dialog.result)
            self._refresh_tree(dialog.result.id)

    def _delete_profile(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            return
        if profile.id in self.pending:
            messagebox.showinfo("Профиль", "Профиль сейчас подключается — подождите.")
            return
        if profile.id in self.mounts and self.mounts[profile.id].alive:
            messagebox.showinfo("Профиль", "Сначала отключите диск.")
            return
        if not messagebox.askyesno(
            "Удалить профиль", f"Удалить профиль «{profile.title}»?\nФайлы ключей останутся на диске."
        ):
            return
        self.store.delete(profile.id)
        self.states.pop(profile.id, None)
        self._refresh_tree()
        self.log(f"Профиль «{profile.title}» удалён")

    # ------------------------------------------------------------------
    # Секреты
    # ------------------------------------------------------------------
    def _ask_password(self, profile: Profile, message: str) -> tuple[str, bool] | None:
        title = f"Пароль SSH — {profile.user}@{profile.host}"
        return ask_secret(self, title, message, save_allowed=True, save_default=bool(profile.save_secret))

    def _collect_secrets(
        self, profile: Profile, *, interactive: bool = True
    ) -> tuple[str, str] | None:
        """Возвращает (пароль для входа, парольная фраза ключа) или None.

        interactive=False — для автоподключения: ничего не спрашиваем, а если
        сохранённых секретов нет, возвращаем None.
        """
        password = ""
        passphrase = ""

        if profile.auth == "agent":
            if not profile.agent_key:
                if interactive:
                    messagebox.showerror(
                        "SSH-агент", "В профиле не выбран ключ. Нажмите «Изменить»."
                    )
                return None
            return password, passphrase  # закрытый ключ остаётся в агенте

        if profile.auth == "password":
            if profile.save_secret and profile.password_enc:
                password = try_unprotect(profile.password_enc) or ""
            if not password:
                if not interactive:
                    return None
                answer = self._ask_password(profile, f"Пароль для {profile.user}@{profile.host}:")
                if answer is None:
                    return None
                password, remember = answer
                if not password:
                    messagebox.showerror("Пароль", "Пароль не введён.")
                    return None
                if remember:
                    profile.password_enc = protect(password)
                    profile.save_secret = True
                    self.store.update(profile)
        else:
            key_path = profile.key_path
            if not key_path or not Path(key_path).exists():
                if interactive:
                    messagebox.showerror(
                        "Ключ",
                        "Ключ не найден. Нажмите «Изменить» → «Создать…», "
                        "затем «Установить ключ».",
                    )
                return None
            if keys.needs_passphrase(key_path):
                if profile.save_secret and profile.passphrase_enc:
                    passphrase = try_unprotect(profile.passphrase_enc) or ""
                if not passphrase:
                    if not interactive:
                        return None
                    answer = ask_secret(
                        self,
                        "Парольная фраза ключа",
                        f"Ключ {Path(key_path).name} зашифрован. Введите парольную фразу:",
                        save_allowed=True,
                        save_default=bool(profile.save_secret),
                    )
                    if answer is None:
                        return None
                    passphrase, remember = answer
                    if remember:
                        profile.passphrase_enc = protect(passphrase)
                        profile.save_secret = True
                        self.store.update(profile)
        return password, passphrase

    # ------------------------------------------------------------------
    # Проверка ключа хоста (вызывается из фонового потока)
    # ------------------------------------------------------------------
    def _ask_yes_no_sync(self, title: str, text: str) -> bool:
        """Показывает вопрос «Да/Нет» из фонового потока; без ответа — «Нет»."""
        event = threading.Event()
        result = {"ok": False}

        def ask() -> None:
            result["ok"] = messagebox.askyesno(title, text, parent=self)
            event.set()

        self.ui(ask)
        event.wait(timeout=300)
        return bool(result["ok"])

    def confirm_host_key(self, host: str, keytype: str, fingerprint: str) -> bool:
        # Сюда доходим только для хоста без сохранённого ключа: если ключ уже
        # известен, а сервер предъявил другой, подключение блокируется раньше.
        return self._ask_yes_no_sync(
            "Новый SSH-сервер",
            f"Хост {host} ещё не известен.\n\n"
            f"Тип ключа: {keytype}\nОтпечаток: {fingerprint}\n\n"
            "Сверьте отпечаток с тем, который вам дал администратор сервера. "
            "Доверять этому серверу и запомнить ключ?",
        )

    def confirm_admin_keys(self) -> bool:
        return self._ask_yes_no_sync(
            "Сервер Windows: учётная запись администратора",
            "Вы вошли на сервер как администратор. Общий файл "
            "administrators_authorized_keys действует для ВСЕХ администраторов "
            "сервера: ключ из него позволит войти под любой из этих учётных записей.\n\n"
            "Добавить ключ и в этот файл? (Обычно хватает «Нет».)",
        )

    # ------------------------------------------------------------------
    # Подключение / отключение
    # ------------------------------------------------------------------
    def _choose_drive(self, profile: Profile, *, auto: bool = False) -> str | None:
        def busy(letter: str) -> bool:
            return rclone.drive_exists(letter) or letter in self.reserved

        if profile.drive:
            if busy(profile.drive):
                if auto:
                    self.log(
                        f"Автоподключение {profile.title}: буква {profile.drive}: уже занята — пропущено",
                        "warn",
                    )
                else:
                    messagebox.showerror("Диск", f"Буква {profile.drive}: уже занята.")
                return None
            return profile.drive

        # При автозапуске стараемся вернуть ту же букву, что была в прошлый раз.
        if profile.last_drive and not busy(profile.last_drive):
            return profile.last_drive

        free = [letter for letter in rclone.free_letters() if letter not in self.reserved]
        if not free:
            if auto:
                self.log(f"Автоподключение {profile.title}: нет свободных букв", "warn")
            else:
                messagebox.showerror("Диск", "Нет свободных букв дисков.")
            return None
        return free[0]

    def _connect_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            return
        self._connect_profile(profile)

    def _connect_profile(self, profile: Profile, *, auto: bool = False) -> None:
        handle = self.mounts.get(profile.id)
        if handle and handle.alive:
            if not auto:
                messagebox.showinfo("Подключение", f"Диск {handle.drive}: уже подключён.")
            return
        if profile.id in self.pending:
            if not auto:
                messagebox.showinfo("Подключение", "Этот профиль уже подключается…")
            return

        if not winfsp.is_installed():
            if auto:
                self.log(
                    f"Автоподключение {profile.title}: WinFsp не установлен — пропущено",
                    "warn",
                )
                self.states[profile.id] = "нужен WinFsp"
                self._refresh_tree(profile.id)
            elif messagebox.askyesno(
                "Нужен WinFsp",
                "Для показа диска в Windows нужен драйвер WinFsp.\nУстановить его сейчас?",
            ):
                self._install_winfsp()
            return
        if not rclone.find_exe():
            if auto:
                self.log(
                    f"Автоподключение {profile.title}: rclone не найден — пропущено",
                    "warn",
                )
                self.states[profile.id] = "нужен rclone"
                self._refresh_tree(profile.id)
            elif messagebox.askyesno("Нужен rclone", "Скачать rclone сейчас?"):
                self._download_rclone()
            return

        secrets = self._collect_secrets(profile, interactive=not auto)
        if secrets is None:
            if auto:
                self.log(
                    f"Автоподключение {profile.title}: нет сохранённого пароля "
                    "или парольной фразы ключа — подключите вручную.",
                    "warn",
                )
                self.states[profile.id] = "нужен пароль"
                self._refresh_tree(profile.id)
            return
        password, passphrase = secrets

        drive = self._choose_drive(profile, auto=auto)
        if drive is None:
            return

        self.reserved.add(drive)
        self.pending_drives[profile.id] = drive
        self.states[profile.id] = "подключение…"
        self.pending.add(profile.id)
        self._refresh_tree(profile.id)

        def work() -> None:
            ok = False
            try:
                pkey = None
                if profile.auth == "key":
                    pkey = keys.load(profile.key_path, passphrase)
                info = sshutil.test_login(
                    profile.host,
                    profile.port,
                    profile.user,
                    password=password if profile.auth == "password" else None,
                    pkey=pkey,
                    agent_key=profile.agent_key if profile.auth == "agent" else None,
                    known_hosts=paths.known_hosts_file(),
                    confirm=self.confirm_host_key,
                )
                self.log(
                    f"{profile.target}: вход выполнен, папка {info['home']}, "
                    f"ключ хоста {info['key_type']} {info['fingerprint']}",
                    "ok",
                )
                handle = rclone.mount(
                    profile,
                    password=password,
                    passphrase=passphrase,
                    drive=drive,
                    host_key=str(info.get("host_key") or ""),
                    on_line=lambda line: self.log(f"rclone: {line}", "dim"),
                )
                self.ui(self._on_mounted, profile, handle)
                ok = True
            finally:
                self.ui(self._connect_finished, profile, ok)

        label = f"Автоподключение {profile.title}" if auto else f"Подключение {profile.title}"
        self.run_bg(label, work)

    def _connect_finished(self, profile: Profile, ok: bool) -> None:
        self.pending.discard(profile.id)
        drive = self.pending_drives.pop(profile.id, None)
        if drive:
            self.reserved.discard(drive)
        if not ok:
            self.states[profile.id] = "ошибка (см. журнал)"
        self._refresh_tree(profile.id)

    def _on_mounted(self, profile: Profile, handle: rclone.MountHandle) -> None:
        self.mounts[profile.id] = handle
        self.pending_drives.pop(profile.id, None)
        self.reserved.discard(handle.drive)
        self.states[profile.id] = f"подключено ({handle.drive}:)"

        # Запоминаем диск, чтобы поднять его при следующем запуске.
        profile.auto_connect = True
        profile.last_drive = handle.drive
        try:
            self.store.update(profile)
        except OSError as exc:
            self.log(f"Не удалось сохранить автоподключение: {exc}", "warn")

        self._refresh_tree(profile.id)
        self.log(f"Диск {handle.drive}: подключён к {profile.target}", "ok")
        threading.Thread(
            target=self._watch_mount, args=(profile, handle), name="mount-watcher", daemon=True
        ).start()

    def _watch_mount(self, profile: Profile, handle: rclone.MountHandle) -> None:
        while handle.alive:
            time.sleep(2)
        self.ui(self._on_mount_exit, profile, handle)

    def _on_mount_exit(self, profile: Profile, handle: rclone.MountHandle) -> None:
        if self.mounts.get(profile.id) is handle:
            self.mounts.pop(profile.id, None)
            self.states[profile.id] = "ошибка: rclone завершился"
            self.log(
                f"Диск {handle.drive}: отключён (rclone код {handle.proc.returncode})", "warn"
            )
            tail = "\n".join(handle.output[-6:])
            if tail:
                self.log(tail, "dim")
        self._refresh_tree(profile.id)

    def _disconnect_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            return
        self._disconnect_profile(profile)

    def _disconnect_profile(self, profile: Profile) -> None:
        handle = self.mounts.get(profile.id)
        if handle is None:
            return
        # Явное отключение = «больше не подключать при старте».
        if profile.auto_connect:
            profile.auto_connect = False
            try:
                self.store.update(profile)
            except OSError as exc:
                self.log(f"Не удалось сохранить профиль: {exc}", "warn")
        self.mounts.pop(profile.id, None)
        self.states[profile.id] = "отключение…"
        self._refresh_tree(profile.id)

        def work() -> None:
            handle.stop()
            self.states[profile.id] = "отключено"
            self.ui(self._refresh_tree, profile.id)
            self.log(f"Диск {handle.drive}: отключён", "ok")

        self.run_bg("Отключение", work)

    def _disconnect_all(self) -> None:
        active = [
            self.store.get(profile_id)
            for profile_id, handle in list(self.mounts.items())
            if handle.alive
        ]
        active = [profile for profile in active if profile is not None]
        if not active:
            self.log("Нет подключённых дисков", "dim")
            return
        self._restore_window()
        for profile in active:
            self._disconnect_profile(profile)

    # ------------------------------------------------------------------
    # Проверка входа и установка ключа
    # ------------------------------------------------------------------
    def _test_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None:
            return
        secrets = self._collect_secrets(profile)
        if secrets is None:
            return
        password, passphrase = secrets

        def work() -> None:
            pkey = keys.load(profile.key_path, passphrase) if profile.auth == "key" else None
            info = sshutil.test_login(
                profile.host,
                profile.port,
                profile.user,
                password=password if profile.auth == "password" else None,
                pkey=pkey,
                agent_key=profile.agent_key if profile.auth == "agent" else None,
                known_hosts=paths.known_hosts_file(),
                confirm=self.confirm_host_key,
            )
            self.log(
                f"Проверка {profile.target}: OK, домашняя папка {info['home']} ({info['version']})",
                "ok",
            )

        self.log(f"Проверяю вход {profile.target}…")
        self.run_bg(f"Проверка {profile.title}", work)

    def _install_key_selected(self) -> None:
        profile = self._selected_profile()
        if profile is None or profile.auth not in ("key", "agent"):
            return
        if profile.auth == "agent":
            self._install_agent_key(profile)
            return
        key_path = Path(profile.key_path) if profile.key_path else keys.default_key_path()

        if not key_path.exists():
            if not messagebox.askyesno(
                "Ключ",
                f"Ключ {key_path} не найден.\nСоздать новую пару ключей?",
            ):
                return
            try:
                path = keys.unique_path(key_path)
                comment = f"{profile.user}@{profile.host}"
                keys.generate(path, comment, "")
            except Exception as exc:  # noqa: BLE001
                messagebox.showerror("Ключ", f"Не удалось создать ключ:\n{exc}")
                return
            profile.key_path = str(path)
            self.store.update(profile)
            self._refresh_tree(profile.id)
            self.log(f"Создан ключ {path}", "ok")
            key_path = path

        passphrase = ""
        if keys.needs_passphrase(key_path):
            if profile.save_secret and profile.passphrase_enc:
                passphrase = try_unprotect(profile.passphrase_enc) or ""
            if not passphrase:
                answer = ask_secret(
                    self,
                    "Парольная фраза ключа",
                    f"Ключ {key_path.name} зашифрован. Введите парольную фразу:",
                    save_allowed=True,
                    save_default=bool(profile.save_secret),
                )
                if answer is None:
                    return
                passphrase, remember = answer
                if remember:
                    profile.passphrase_enc = protect(passphrase)
                    profile.save_secret = True
                    self.store.update(profile)

        stored_password = ""
        if profile.save_secret and profile.password_enc:
            stored_password = try_unprotect(profile.password_enc) or ""

        pubkey = keys.public_line(key_path, passphrase)

        self.log(f"Устанавливаю ключ {key_path.name} на {profile.target}…")
        self.run_bg(
            "Установка ключа",
            lambda: self._install_key_work(
                profile, pubkey, stored_password,
                lambda: {"pkey": keys.load(key_path, passphrase)},
            ),
        )

    def _install_agent_key(self, profile: Profile) -> None:
        """Добавляет на сервер публичный ключ, который держит SSH-агент."""
        if not profile.agent_key:
            messagebox.showerror("SSH-агент", "В профиле не выбран ключ. Нажмите «Изменить».")
            return
        comment = keys.sanitize_comment(profile.agent_comment or f"{profile.user}@{profile.host}")
        pubkey = f"{profile.agent_key} {comment}".strip()
        stored_password = ""
        if profile.save_secret and profile.password_enc:
            stored_password = try_unprotect(profile.password_enc) or ""
        self.log(f"Устанавливаю ключ из агента на {profile.target}…")
        self.run_bg(
            "Установка ключа",
            lambda: self._install_key_work(
                profile, pubkey, stored_password, lambda: {"agent_key": profile.agent_key}
            ),
        )

    def _install_key_work(
        self, profile: Profile, pubkey: str, stored_password: str, login_kwargs
    ) -> None:
        """Фоновая часть установки ключа (файловый ключ или ключ из агента).

        login_kwargs() даёт параметры входа по ключу для sshutil.test_login.
        """

        def login() -> dict:
            return sshutil.test_login(
                profile.host,
                profile.port,
                profile.user,
                known_hosts=paths.known_hosts_file(),
                confirm=self.confirm_host_key,
                **login_kwargs(),
            )

        try:
            info = login()
            self.log(f"Ключ уже работает: {profile.target} → {info['home']}", "ok")
            return
        except sshutil.SSHError as exc:
            if "отклонил вход" not in str(exc):
                raise
            self.log("Ключ на сервере ещё не установлен — добавляю через вход по паролю…")

        password = stored_password
        if not password:
            answer = self.ask_secret_sync(
                "Пароль SSH",
                f"Пароль {profile.user}@{profile.host} нужен один раз, "
                "чтобы добавить ключ на сервер.",
                save_allowed=True,
                save_default=bool(profile.save_secret),
            )
            if answer is None:
                self.log("Установка ключа отменена", "warn")
                return
            password, remember = answer
            if not password:
                self.log("Установка ключа отменена: пустой пароль", "warn")
                return
            if remember:
                self.ui(self._remember_password, profile, password)

        client = sshutil.connect(
            profile.host,
            profile.port,
            profile.user,
            password=password,
            known_hosts=paths.known_hosts_file(),
            confirm=self.confirm_host_key,
        )
        try:
            result = sshutil.install_public_key(
                client, pubkey, confirm_admin=self.confirm_admin_keys
            )
        finally:
            client.close()
        self.log(f"Сервер: {result}", "ok")

        info = login()
        self.log(f"Готово: вход по ключу работает, домашняя папка {info['home']}", "ok")

    def _remember_password(self, profile: Profile, password: str) -> None:
        profile.password_enc = protect(password)
        profile.save_secret = True
        self.store.update(profile)

    def ask_secret_sync(
        self, title: str, message: str, *, save_allowed: bool = False, save_default: bool = True
    ) -> tuple[str, bool] | None:
        """Показывает диалог пароля из фонового потока и ждёт ответа."""
        event = threading.Event()
        box: dict[str, tuple[str, bool] | None] = {}
        self.ui(
            self._show_secret_dialog,
            box,
            event,
            title,
            message,
            save_allowed,
            save_default,
        )
        event.wait(timeout=900)
        return box.get("answer")

    def _show_secret_dialog(self, box, event, title, message, save_allowed, save_default) -> None:
        box["answer"] = ask_secret(
            self, title, message, save_allowed=save_allowed, save_default=save_default
        )
        event.set()

    # ------------------------------------------------------------------
    # Окружение: rclone, WinFsp
    # ------------------------------------------------------------------
    def _update_env(self, rclone_version: str, winfsp_version: str) -> None:
        parts = [
            f"rclone: {rclone_version}" if rclone_version else "rclone: не найден",
            f"WinFsp: {winfsp_version}" if winfsp_version else "WinFsp: не найден",
        ]
        self.env_var.set("   |   ".join(parts))

    def _startup_checks(self, auto: bool = False) -> None:
        def work() -> None:
            exe = rclone.find_exe()
            version = rclone.version(exe) if exe else ""
            installed = winfsp.is_installed()
            driver = (winfsp.version() or "установлен") if installed else ""
            self.ui(self._update_env, version, driver)
            if not exe:
                self.log("rclone не найден — без него нельзя создать диск.", "warn")
                self.ui(self._offer_rclone)
            else:
                self.log(f"rclone {version} найден: {exe}")
            if not installed:
                self.log("WinFsp не найден — драйвер нужен для диска в Windows.", "warn")
                self.ui(self._offer_winfsp)
            else:
                self.log(f"WinFsp {driver} установлен")
            if version and installed:
                self.log("Окружение готово. Можно подключать диск.", "ok")
            if auto:
                self.ui(self._autoconnect)

        self.run_bg("Проверка окружения", work)

    def _check_environment(self) -> None:
        self.log("Проверяю окружение…")
        self._startup_checks()

    def _autoconnect(self) -> None:
        """Поднимает диски, которые были подключены при прошлом запуске."""
        if self._autoconnect_done or self.smoke:
            return
        targets = [profile for profile in self.store.profiles if profile.auto_connect]
        if not targets:
            self._autoconnect_done = True
            return
        if not winfsp.is_installed() or not rclone.find_exe():
            self._autoconnect_pending = True
            self.log(
                "Автоподключение отложено: сначала нужны WinFsp и rclone.", "warn"
            )
            return
        self._autoconnect_done = True
        self._autoconnect_pending = False
        self.log(
            f"Автоподключение при запуске: профилей {len(targets)}",
            "info",
        )
        for profile in targets:
            self._connect_profile(profile, auto=True)

    def _offer_rclone(self) -> None:
        if self._asked_rclone or self.smoke or os.environ.get("SSHDRIVE_NO_PROMPTS") == "1":
            return
        self._asked_rclone = True
        if messagebox.askyesno(
            "rclone",
            "rclone не найден (это движок монтирования).\nСкачать официальную сборку (~30 МБ) сейчас?",
        ):
            self._download_rclone()

    def _offer_winfsp(self) -> None:
        if self._asked_winfsp or self.smoke or os.environ.get("SSHDRIVE_NO_PROMPTS") == "1":
            return
        self._asked_winfsp = True
        if messagebox.askyesno(
            "WinFsp",
            "WinFsp не найден — это драйвер, через который Windows видит SSH-папку как диск.\n\n"
            "Установить официальный WinFsp сейчас? Потребуется подтверждение UAC.",
        ):
            self._install_winfsp()

    def _download_rclone(self) -> None:
        self.log("Скачиваю rclone…")

        def work() -> None:
            exe = rclone.download_executable(progress=self._progress, log=self.log)
            version = rclone.version(exe)
            self.ui(self._update_env, version, winfsp.version() if winfsp.is_installed() else "")
            self.log(f"rclone {version} готов", "ok")
            if self._autoconnect_pending:
                self.ui(self._autoconnect)

        self.run_bg("Скачивание rclone", work)

    def _install_winfsp(self) -> None:
        self.log("Устанавливаю WinFsp…")

        def work() -> None:
            winfsp.install(progress=self._progress, log=self.log)
            installed = winfsp.is_installed()
            version = (winfsp.version() or "установлен") if installed else ""
            self.ui(
                self._update_env,
                rclone.version() if rclone.find_exe() else "",
                version,
            )
            self.log(f"WinFsp {version or 'не установлен'}", "ok" if installed else "err")
            if installed and self._autoconnect_pending:
                self.ui(self._autoconnect)

        self.run_bg("Установка WinFsp", work)

    # ------------------------------------------------------------------
    # Меню
    # ------------------------------------------------------------------
    def _show_known_hosts(self) -> None:
        dialog = KnownHostsDialog(self)
        self.wait_window(dialog)

    def _open_data_dir(self) -> None:
        try:
            os.startfile(str(paths.appdata_dir()))  # noqa: S606 - Windows shell
        except OSError as exc:
            messagebox.showerror("Папка данных", str(exc))

    def _open_readme(self) -> None:
        candidates = [
            paths.bundled_file("README.md"),
            paths.install_dir() / "README.md",
            Path(__file__).resolve().parent.parent / "README.md",
        ]
        readme = next((p for p in candidates if p is not None and p.exists()), None)
        if readme is not None:
            os.startfile(str(readme))  # noqa: S606
        else:
            messagebox.showinfo("Справка", "README.md не найден рядом с программой.")

    def _clear_log(self) -> None:
        self.log_text.configure(state="normal")
        self.log_text.delete("1.0", "end")
        self.log_text.configure(state="disabled")

    def _about(self) -> None:
        messagebox.showinfo(
            "SSH Drive",
            "SSH Drive 1.1\n\n"
            "Монтирует папку SSH-сервера как диск Windows.\n"
            "Движок: rclone + WinFsp, интерфейс: tkinter.\n"
            "Закрытие окна сворачивает программу в трей; выход — через меню иконки.\n"
            "Подключённые диски запоминаются и поднимаются при следующем запуске.\n"
            "Пароли хранятся в profiles.json в зашифрованном виде (DPAPI, текущий пользователь Windows).",
        )

    # ------------------------------------------------------------------
    # Завершение
    # ------------------------------------------------------------------
    def _on_close(self) -> None:
        """Крестик окна: свернуть в трей — диски продолжают работать."""
        if self._quitting:
            return
        if self.smoke or not self.tray_ok:
            self._quit()
            return
        self.hide_to_tray()

    def _quit(self) -> None:
        """Настоящий выход: отключить диски, убрать иконку и закрыть программу."""
        if self._quitting:
            return
        if self.pending:
            self._restore_window()
            messagebox.showinfo(
                "Выход",
                "Идёт подключение. Дождитесь его завершения (обычно несколько секунд).",
            )
            return
        active = [h for h in self.mounts.values() if h.alive]
        if active:
            self._restore_window()
            if not messagebox.askyesno(
                "Выход", f"Активных дисков: {len(active)}. Отключить их и выйти?"
            ):
                return
            for handle in active:
                try:
                    handle.stop(timeout=6)
                except Exception as exc:  # noqa: BLE001
                    self.log(f"Не удалось отключить {handle.drive}: {exc}", "warn")
        self._quitting = True
        if self._drain_id is not None:
            try:
                self.after_cancel(self._drain_id)
            except tk.TclError:
                pass
            self._drain_id = None
        if self.tray is not None:
            self.tray.stop()
        self.destroy()


_MUTEX = None


def _acquire_single_instance() -> bool:
    """Не даём открыть два окна: иначе два процесса могут драться за буквы дисков."""
    global _MUTEX
    if os.name != "nt":
        return True
    import ctypes
    from ctypes import wintypes

    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    ctypes.set_last_error(0)
    name = "Local\\SSHDrive.SingleInstance"
    suffix = os.environ.get("SSHDRIVE_INSTANCE", "").strip()
    if suffix:
        # отладочный запуск второго экземпляра рядом с рабочим
        name += "." + suffix
    handle = kernel32.CreateMutexW(None, False, name)
    if not handle:
        return True
    if ctypes.get_last_error() == 183:  # ERROR_ALREADY_EXISTS
        kernel32.CloseHandle(handle)
        return False
    _MUTEX = handle
    return True


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    smoke = "--smoke" in argv
    if not smoke and not _acquire_single_instance():
        root = tk.Tk()
        root.withdraw()
        messagebox.showinfo(
            "SSH Drive",
            "SSH Drive уже запущен.\n\n"
            "Окно могло быть свёрнуто в трей — посмотрите иконку рядом с часами "
            "(двойной клик открывает окно).",
            parent=root,
        )
        root.destroy()
        return 0
    app = App(smoke=smoke, start_hidden=("--tray" in argv))
    if smoke:
        app.after(1800, app.destroy)
    app.mainloop()
    if smoke:
        try:
            print("SMOKE OK")
        except Exception:  # noqa: BLE001 - в windowed-сборке stdout может отсутствовать
            pass
    return 0
