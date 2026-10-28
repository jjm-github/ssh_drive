"""GUI SSH Share — общий доступ к папке по SSH/SFTP (tkinter)."""

from __future__ import annotations

import os
import queue
import socket
import threading
import time
import traceback
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import asyncssh

from . import __version__, paths
from .config import (
    ConfigStore,
    MIN_PASSWORD_LENGTH,
    ShareConfig,
    ShareUser,
    USER_NAME_RE,
    check_new_password,
    hash_password,
    validate_share,
)
from .server import ShareError, ShareServer

LEVEL_COLORS = {
    "info": "#202020",
    "ok": "#1a7f37",
    "warn": "#9a6700",
    "err": "#b42318",
    "dim": "#6e7781",
}


def parse_public_key(line: str) -> str:
    """Приводит строку authorized_keys к каноническому публичному ключу."""
    line = line.strip()
    if not line or line.startswith("#"):
        return ""
    candidates = [line]
    parts = line.split()
    for index, part in enumerate(parts):
        if part.startswith(("ssh-", "ecdsa-", "sk-")):
            candidates.append(" ".join(parts[index:]))
            break
    for candidate in candidates:
        try:
            return asyncssh.import_public_key(candidate).export_public_key().decode("ascii")
        except Exception:
            continue
    raise ValueError("не похоже на публичный ключ OpenSSH")


def make_icon(size: int = 64):
    from PIL import Image, ImageDraw

    scale = size / 64.0
    image = Image.new("RGBA", (size, size), (0, 0, 0, 0))
    draw = ImageDraw.Draw(image)

    def p(value: float) -> float:
        return value * scale

    draw.rounded_rectangle([p(2), p(2), p(62), p(62)], radius=p(14), fill=(15, 118, 110, 255))
    draw.polygon(
        [(p(13), p(21)), (p(27), p(21)), (p(31), p(26)), (p(51), p(26)),
         (p(51), p(45)), (p(13), p(45))],
        fill=(255, 255, 255, 255),
    )
    draw.polygon(
        [(p(36), p(30)), (p(46), p(35.5)), (p(36), p(41))],
        fill=(15, 118, 110, 255),
    )
    return image


class UserDialog(tk.Toplevel):
    """Добавление/редактирование пользователя SSH Share."""

    def __init__(self, parent: tk.Misc, user: ShareUser, existing: set[str]) -> None:
        super().__init__(parent)
        self.result: ShareUser | None = None
        self._user = user
        self._existing = existing
        self._is_new = not user.name

        self.title("Пользователь SSH Share")
        self.resizable(False, False)
        self.transient(parent)

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        body.columnconfigure(1, weight=1)

        self.name = tk.StringVar(value=user.name)
        self.password = tk.StringVar()
        self.show_password = tk.BooleanVar(value=False)
        self.remove_password = tk.BooleanVar(value=False)
        self.read_only = tk.BooleanVar(value=user.read_only)

        row = 0
        ttk.Label(body, text="Имя пользователя").grid(row=row, column=0, sticky="w", pady=3)
        ttk.Entry(body, textvariable=self.name, width=36).grid(
            row=row, column=1, sticky="ew", pady=3
        )
        row += 1
        ttk.Label(
            body,
            text="латиница, цифры, . _ - (до 32 символов)",
            foreground="#666666",
        ).grid(row=row, column=1, sticky="w")

        row += 1
        ttk.Label(body, text="Пароль").grid(row=row, column=0, sticky="w", pady=(10, 3))
        password_frame = ttk.Frame(body)
        password_frame.grid(row=row, column=1, sticky="ew", pady=(10, 3))
        password_frame.columnconfigure(0, weight=1)
        self.password_entry = ttk.Entry(
            password_frame, textvariable=self.password, show="•"
        )
        self.password_entry.grid(row=0, column=0, sticky="ew")
        ttk.Checkbutton(
            password_frame,
            text="показать",
            variable=self.show_password,
            command=self._toggle_password,
        ).grid(row=0, column=1, padx=(8, 0))
        row += 1
        if user.has_password:
            ttk.Checkbutton(
                body,
                text="Удалить сохранённый пароль (оставить только ключи)",
                variable=self.remove_password,
            ).grid(row=row, column=1, sticky="w")
            row += 1
        ttk.Label(
            body,
            text=f"не меньше {MIN_PASSWORD_LENGTH} символов; пусто = не менять сохранённый пароль",
            foreground="#666666",
        ).grid(row=row, column=1, sticky="w")

        row += 1
        ttk.Label(body, text="Публичные ключи").grid(row=row, column=0, sticky="nw", pady=(12, 3))
        keys_frame = ttk.Frame(body)
        keys_frame.grid(row=row, column=1, sticky="nsew", pady=(12, 3))
        keys_frame.columnconfigure(0, weight=1)
        self.keys_text = tk.Text(keys_frame, height=6, width=52, wrap="none", font=("Consolas", 9))
        self.keys_text.grid(row=0, column=0, sticky="nsew")
        keys_scroll = ttk.Scrollbar(keys_frame, orient="vertical", command=self.keys_text.yview)
        keys_scroll.grid(row=0, column=1, sticky="ns")
        self.keys_text.configure(yscrollcommand=keys_scroll.set)
        self.keys_text.insert("1.0", "\n".join(user.keys))
        ttk.Button(keys_frame, text="Загрузить .pub…", command=self._load_key).grid(
            row=1, column=0, sticky="w", pady=(4, 0)
        )

        row += 1
        ttk.Label(
            body,
            text="по одному ключу на строку; нужен пароль или хотя бы один ключ",
            foreground="#666666",
        ).grid(row=row, column=1, sticky="w")

        row += 1
        ttk.Checkbutton(
            body,
            text="Только чтение (нельзя изменять файлы)",
            variable=self.read_only,
        ).grid(row=row, column=1, sticky="w", pady=(10, 0))

        row += 1
        buttons = ttk.Frame(body)
        buttons.grid(row=row, column=0, columnspan=2, sticky="e", pady=(16, 0))
        ttk.Button(buttons, text="Отмена", command=self._cancel).pack(side="right")
        ttk.Button(buttons, text="Сохранить", command=self._ok, style="Accent.TButton").pack(
            side="right", padx=(0, 8)
        )

        self.bind("<Escape>", lambda _event: self._cancel())
        self.protocol("WM_DELETE_WINDOW", self._cancel)
        self._center(parent)
        self.grab_set()

    def _center(self, parent: tk.Misc) -> None:
        self.update_idletasks()
        x = parent.winfo_rootx() + (parent.winfo_width() - self.winfo_width()) // 2
        y = parent.winfo_rooty() + (parent.winfo_height() - self.winfo_height()) // 3
        self.geometry(f"+{max(0, x)}+{max(0, y)}")

    def _toggle_password(self) -> None:
        self.password_entry.configure(show="" if self.show_password.get() else "•")

    def _load_key(self) -> None:
        path = filedialog.askopenfilename(
            parent=self,
            title="Публичный ключ",
            filetypes=[("Публичные ключи", "*.pub id_*"), ("Все файлы", "*.*")],
        )
        if not path:
            return
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace").strip()
        except OSError as exc:
            messagebox.showerror("Ключ", str(exc), parent=self)
            return
        current = self.keys_text.get("1.0", "end").strip()
        self.keys_text.delete("1.0", "end")
        self.keys_text.insert("1.0", (current + "\n" if current else "") + text + "\n")

    def _ok(self) -> None:
        name = self.name.get().strip()
        if not USER_NAME_RE.fullmatch(name):
            messagebox.showerror(
                "Пользователь",
                "Имя: латиница, цифры, точка, дефис и подчёркивание, до 32 символов.",
                parent=self,
            )
            return
        if name.lower() in self._existing:
            messagebox.showerror("Пользователь", f"«{name}» уже есть.", parent=self)
            return

        keys: list[str] = []
        for line in self.keys_text.get("1.0", "end").splitlines():
            try:
                key = parse_public_key(line)
            except ValueError as exc:
                messagebox.showerror("Ключ", f"{line.strip()[:60]}…\n{exc}", parent=self)
                return
            if key and key not in keys:
                keys.append(key)

        password_hash = self._user.password_hash
        password_enc = self._user.password_enc  # устаревшая запись, перенесётся при запуске
        if self.remove_password.get():
            password_hash = password_enc = ""
        elif self.password.get():
            problem = check_new_password(self.password.get())
            if problem:
                messagebox.showerror("Пароль", problem, parent=self)
                return
            password_hash, password_enc = hash_password(self.password.get()), ""

        if not password_hash and not password_enc and not keys:
            messagebox.showerror(
                "Пользователь",
                "Нужен пароль или хотя бы один публичный ключ.",
                parent=self,
            )
            return

        self.result = ShareUser(
            name=name,
            password_hash=password_hash,
            password_enc=password_enc,
            keys=keys,
            read_only=bool(self.read_only.get()),
        )
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


class App(tk.Tk):
    def __init__(self, smoke: bool = False) -> None:
        super().__init__()
        paths.ensure_dirs()
        self.smoke = smoke
        self.store = ConfigStore()
        self.config = self.store.config
        self.server: ShareServer | None = None
        self._busy = False
        self._queue: queue.Queue = queue.Queue()
        self._log_lock = threading.Lock()
        self._drain_id = None
        self._smoke_close_id = None

        self.title("SSH Share — общий доступ к папке по SSH")
        self.geometry("1000x700")
        self.minsize(880, 600)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self._set_icon()
        self._init_style()
        self._build_menu()
        self._build_ui()
        self._refresh_users()
        self._update_controls()
        self._drain_id = self.after(100, self._drain)
        self.log(f"Данные SSH Share: {paths.appdata_dir()}", "dim")

        if self.config.folder:
            self.folder_var.set(self.config.folder)
        self.port_var.set(str(self.config.port))
        self.bind_var.set(self._bind_label(self.config.bind))
        self.status_var.set("Остановлен")

        self.after(200, self._check_environment)
        if self.smoke:
            self._smoke_close_id = self.after(1800, self._on_close)

    # ------------------------------------------------------------------
    # Оформление и журнал
    # ------------------------------------------------------------------
    def _init_style(self) -> None:
        style = ttk.Style(self)
        for theme in ("vista", "winnative", "clam"):
            if theme in style.theme_names():
                style.theme_use(theme)
                break
        style.configure("Accent.TButton", font=("Segoe UI", 9, "bold"))
        style.configure("Treeview", rowheight=24)

    def _set_icon(self) -> None:
        try:
            from PIL import ImageTk

            self._icon_photo = ImageTk.PhotoImage(make_icon(64))
            self.iconphoto(True, self._icon_photo)
        except Exception:  # noqa: BLE001
            self._icon_photo = None

    def log(self, message: str, level: str = "info") -> None:
        stamp = time.strftime("%H:%M:%S")
        self._queue.put(("log", f"[{stamp}] {message}", level))
        try:
            with self._log_lock:
                with paths.log_file().open("a", encoding="utf-8") as handle:
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
            except Exception as exc:  # noqa: BLE001
                self.log(f"{label}: {type(exc).__name__}: {exc}", "err")
                if os.environ.get("SSH_SHARE_DEBUG"):
                    self.log(traceback.format_exc(), "dim")

        threading.Thread(target=runner, name=label, daemon=True).start()

    def _drain(self) -> None:
        try:
            while True:
                kind, payload, extra = self._queue.get_nowait()
                if kind == "log":
                    self.log_text.configure(state="normal")
                    self.log_text.insert("end", payload + "\n", extra)
                    self.log_text.see("end")
                    self.log_text.configure(state="disabled")
                elif kind == "ui":
                    try:
                        payload(*extra)
                    except Exception:  # noqa: BLE001
                        self.log_text.configure(state="normal")
                        self.log_text.insert("end", traceback.format_exc(), "err")
                        self.log_text.configure(state="disabled")
        except queue.Empty:
            pass
        self._drain_id = self.after(100, self._drain)

    # ------------------------------------------------------------------
    # Интерфейс
    # ------------------------------------------------------------------
    def _build_menu(self) -> None:
        menu = tk.Menu(self)
        file_menu = tk.Menu(menu, tearoff=False)
        file_menu.add_command(label="Выход", command=self._on_close)
        menu.add_cascade(label="Файл", menu=file_menu)

        tools = tk.Menu(menu, tearoff=False)
        tools.add_command(label="Открыть папку данных", command=self._open_data_dir)
        tools.add_command(label="README", command=self._open_readme)
        menu.add_cascade(label="Сервис", menu=tools)

        help_menu = tk.Menu(menu, tearoff=False)
        help_menu.add_command(label="О программе", command=self._about)
        menu.add_cascade(label="Справка", menu=help_menu)
        self.configure(menu=menu)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=12)
        outer.pack(fill="both", expand=True)

        settings = ttk.LabelFrame(outer, text="Что и как раздаём", padding=10)
        settings.pack(fill="x")
        settings.columnconfigure(1, weight=1)

        ttk.Label(settings, text="Папка").grid(row=0, column=0, sticky="w")
        self.folder_var = tk.StringVar()
        self.folder_entry = ttk.Entry(settings, textvariable=self.folder_var)
        self.folder_entry.grid(row=0, column=1, sticky="ew", padx=6)
        self.folder_button = ttk.Button(settings, text="Обзор…", command=self._browse_folder)
        self.folder_button.grid(row=0, column=2)

        ttk.Label(settings, text="Порт").grid(row=1, column=0, sticky="w", pady=(8, 0))
        port_frame = ttk.Frame(settings)
        port_frame.grid(row=1, column=1, sticky="w", padx=6, pady=(8, 0))
        self.port_var = tk.StringVar(value="2222")
        self.port_entry = ttk.Entry(port_frame, textvariable=self.port_var, width=8)
        self.port_entry.pack(side="left")

        self.bind_var = tk.StringVar()
        self.bind_combo = ttk.Combobox(
            settings,
            textvariable=self.bind_var,
            state="readonly",
            width=34,
            values=[
                "Все интерфейсы (0.0.0.0)",
                "Только этот компьютер (127.0.0.1)",
            ],
        )
        self.bind_var.set("Все интерфейсы (0.0.0.0)")
        self.bind_combo.grid(row=1, column=2, sticky="e", pady=(8, 0))

        users = ttk.LabelFrame(outer, text="Пользователи", padding=10)
        users.pack(fill="both", expand=True, pady=(10, 0))
        toolbar = ttk.Frame(users)
        toolbar.pack(fill="x", pady=(0, 6))
        self.btn_add = ttk.Button(toolbar, text="Добавить", command=self._add_user)
        self.btn_edit = ttk.Button(toolbar, text="Изменить", command=self._edit_user)
        self.btn_delete = ttk.Button(toolbar, text="Удалить", command=self._delete_user)
        for button in (self.btn_add, self.btn_edit, self.btn_delete):
            button.pack(side="left", padx=(0, 6))

        columns = ("name", "auth", "access")
        self.users_tree = ttk.Treeview(users, columns=columns, show="headings", height=6)
        for column, title, width in (
            ("name", "Имя", 220),
            ("auth", "Вход", 180),
            ("access", "Доступ", 160),
        ):
            self.users_tree.heading(column, text=title)
            self.users_tree.column(column, width=width, anchor="w")
        self.users_tree.pack(fill="both", expand=True)
        self.users_tree.bind("<<TreeviewSelect>>", lambda _event: self._update_controls())
        self.users_tree.bind("<Double-1>", lambda _event: self._edit_user())

        control = ttk.Frame(outer)
        control.pack(fill="x", pady=(10, 0))
        self.start_button = ttk.Button(
            control, text="Запустить сервер", command=self._start, style="Accent.TButton"
        )
        self.stop_button = ttk.Button(control, text="Остановить", command=self._stop)
        self.start_button.pack(side="left")
        self.stop_button.pack(side="left", padx=(8, 0))
        self.status_var = tk.StringVar(value="Остановлен")
        ttk.Label(control, textvariable=self.status_var, foreground="#444444").pack(
            side="left", padx=(16, 0)
        )

        info_frame = ttk.LabelFrame(outer, text="Подключение", padding=8)
        info_frame.pack(fill="x", pady=(10, 0))
        self.info_text = tk.Text(
            info_frame,
            height=4,
            wrap="word",
            state="disabled",
            font=("Consolas", 9),
            background="#fbfbfd",
            relief="flat",
        )
        self.info_text.pack(fill="x")
        info_buttons = ttk.Frame(info_frame)
        info_buttons.pack(fill="x", pady=(4, 0))
        ttk.Button(info_buttons, text="Скопировать", command=self._copy_info).pack(side="left")
        ttk.Label(
            info_buttons,
            text="если клиент не подключается — разрешите порт в брандмауэре Windows",
            foreground="#666666",
        ).pack(side="left", padx=(10, 0))

        log_frame = ttk.LabelFrame(outer, text="Журнал", padding=6)
        log_frame.pack(fill="both", expand=True, pady=(10, 0))
        self.log_text = tk.Text(
            log_frame,
            height=8,
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

    def _bind_label(self, bind: str) -> str:
        return (
            "Только этот компьютер (127.0.0.1)"
            if bind == "127.0.0.1"
            else "Все интерфейсы (0.0.0.0)"
        )

    # ------------------------------------------------------------------
    # Пользователи
    # ------------------------------------------------------------------
    def _refresh_users(self) -> None:
        self.users_tree.delete(*self.users_tree.get_children())
        for user in self.config.users:
            self.users_tree.insert(
                "", "end", iid=user.name, values=(user.name, user.auth_label(), user.access_label())
            )
        self._update_controls()

    def _selected_user(self) -> ShareUser | None:
        selection = self.users_tree.selection()
        return self.config.user(selection[0]) if selection else None

    def _add_user(self) -> None:
        names = {user.name.lower() for user in self.config.users}
        dialog = UserDialog(self, ShareUser(), names)
        self.wait_window(dialog)
        if dialog.result:
            self.config.users.append(dialog.result)
            self._save()
            self._refresh_users()

    def _edit_user(self) -> None:
        user = self._selected_user()
        if user is None:
            return
        names = {item.name.lower() for item in self.config.users if item is not user}
        dialog = UserDialog(self, user, names)
        self.wait_window(dialog)
        if dialog.result:
            index = self.config.users.index(user)
            self.config.users[index] = dialog.result
            self._save()
            self._refresh_users()

    def _delete_user(self) -> None:
        user = self._selected_user()
        if user is None:
            return
        if not messagebox.askyesno(
            "Пользователь", f"Удалить пользователя «{user.name}»?", parent=self
        ):
            return
        self.config.users.remove(user)
        self._save()
        self._refresh_users()

    def _browse_folder(self) -> None:
        initial = self.folder_var.get() or str(Path.home())
        chosen = filedialog.askdirectory(parent=self, title="Папка для общего доступа", initialdir=initial)
        if chosen:
            self.folder_var.set(chosen)

    def _apply_ui(self) -> None:
        self.config.folder = self.folder_var.get().strip()
        try:
            self.config.port = int(self.port_var.get())
        except ValueError:
            self.config.port = -1
        self.config.bind = "127.0.0.1" if self.bind_var.get().startswith("Только") else "0.0.0.0"

    def _save(self) -> None:
        try:
            self.store.save()
        except OSError as exc:
            self.log(f"Не удалось сохранить настройки: {exc}", "err")

    # ------------------------------------------------------------------
    # Запуск/остановка
    # ------------------------------------------------------------------
    def _update_controls(self) -> None:
        running = self.server is not None and self.server.running
        user_selected = self._selected_user() is not None
        state = "disabled" if self._busy or running else "normal"
        for widget in (self.folder_entry, self.folder_button, self.port_entry, self.bind_combo):
            widget.configure(state=state)
        for widget in (self.btn_add, self.btn_edit, self.btn_delete):
            widget.configure(state="disabled" if self._busy or running else "normal")
        self.btn_edit.configure(state="normal" if user_selected and not running else "disabled")
        self.btn_delete.configure(state="normal" if user_selected and not running else "disabled")
        self.start_button.configure(state="disabled" if running or self._busy else "normal")
        self.stop_button.configure(state="normal" if running and not self._busy else "disabled")

    def _start(self) -> None:
        if self._busy or (self.server and self.server.running):
            return
        self._apply_ui()
        try:
            validate_share(self.config)
        except ShareError as exc:
            messagebox.showerror("SSH Share", str(exc), parent=self)
            return
        self._save()
        self._busy = True
        self.status_var.set("Запуск…")
        self._update_controls()
        config = ShareConfig.from_dict(self.config.to_dict())

        def work() -> None:
            server = ShareServer(config, log=self.log)
            try:
                server.start()
            except Exception as exc:  # noqa: BLE001
                self.ui(self._start_failed, str(exc))
                return
            self.ui(self._started, server)

        self.log(f"Запускаю сервер {self.config.bind}:{self.config.port}…")
        self.run_bg("Запуск сервера", work)

    def _start_failed(self, message: str) -> None:
        self._busy = False
        self.status_var.set("Остановлен")
        self.log(f"Не удалось запустить сервер: {message}", "err")
        self._update_controls()
        messagebox.showerror("SSH Share", f"Не удалось запустить сервер:\n{message}", parent=self)

    def _started(self, server: ShareServer) -> None:
        self._busy = False
        self.server = server
        self.status_var.set(f"Работает · {self.config.bind}:{server.port}")
        self._update_controls()
        self._update_info()
        self.log(f"Сервер запущен на {self.config.bind}:{server.port}", "ok")

    def _stop(self) -> None:
        server = self.server
        if server is None:
            return
        self._busy = True
        self.status_var.set("Остановка…")
        self._update_controls()

        def work() -> None:
            try:
                server.stop()
            finally:
                self.ui(self._stopped)

        self.run_bg("Остановка сервера", work)

    def _stopped(self) -> None:
        self._busy = False
        self.server = None
        self.status_var.set("Остановлен")
        self._update_controls()
        self._update_info()
        self.log("Сервер остановлен", "info")

    def _update_info(self) -> None:
        lines = []
        if self.config.folder:
            lines.append(f"Папка: {self.config.folder}")
        if self.server is not None and self.server.running:
            port = self.server.port
            if self.config.bind == "127.0.0.1":
                addresses = [f"127.0.0.1:{port}"]
            else:
                addresses = [f"{ip}:{port}" for ip in self._local_ips()]
                addresses.append(f"127.0.0.1:{port}")
            lines.append("Адрес: " + ", ".join(addresses))
            lines.append(f"Ключ сервера: {self.server.fingerprint()}")
            users = ", ".join(
                f"{user.name} ({user.auth_label()}, {user.access_label()})"
                for user in self.config.users
            )
            lines.append(f"Пользователи: {users}")
        else:
            lines.append("Сервер остановлен.")
        self.info_text.configure(state="normal")
        self.info_text.delete("1.0", "end")
        self.info_text.insert("1.0", "\n".join(lines))
        self.info_text.configure(state="disabled")

    def _local_ips(self) -> list[str]:
        result: set[str] = set()
        try:
            for item in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
                address = item[4][0]
                if not address.startswith("127.") and not address.startswith("169.254."):
                    result.add(address)
        except OSError:
            pass
        return sorted(result)

    def _copy_info(self) -> None:
        text = self.info_text.get("1.0", "end").strip()
        self.clipboard_clear()
        self.clipboard_append(text)
        self.log("Информация о подключении скопирована", "dim")

    def _check_environment(self) -> None:
        port = self.config.port
        if 0 < port < 1024:
            self.log(
                f"Порт {port} меньше 1024: для него могут понадобиться права администратора.",
                "warn",
            )
        if not self.config.users:
            self.log("Пользователей пока нет — добавьте хотя бы одного.", "warn")
        self._update_info()

    # ------------------------------------------------------------------
    # Меню/выход
    # ------------------------------------------------------------------
    def _open_data_dir(self) -> None:
        
        try:
            os.startfile(str(paths.appdata_dir()))  # noqa: S606
        except OSError as exc:
            messagebox.showerror("Папка данных", str(exc), parent=self)

    def _open_readme(self) -> None:
        
        candidates = [
            paths.appdata_dir() / "README.md",
            Path(__file__).resolve().parent.parent / "README.md",
        ]
        readme = next((path for path in candidates if path.is_file()), None)
        if readme is not None:
            os.startfile(str(readme))  # noqa: S606
        else:
            messagebox.showinfo("Справка", "README.md не найден рядом с программой.", parent=self)

    def _about(self) -> None:
        messagebox.showinfo(
            "SSH Share",
            f"SSH Share {__version__}\n\n"
            "Отдаёт выбранную папку по SSH/SFTP.\n"
            "Пользователи: пароль и/или публичные ключи, режим «только чтение».\n"
            "Папка заперта (chroot), выход за её пределы запрещён.\n\n"
            "Данные: %APPDATA%\\SSHShare, журнал: %LOCALAPPDATA%\\SSHShare.",
            parent=self,
        )

    def _on_close(self) -> None:
        if self._busy:
            messagebox.showinfo("Выход", "Дождитесь завершения операции.", parent=self)
            return
        if self.server is not None and self.server.running:
            if not messagebox.askyesno(
                "Выход", "Сервер работает. Остановить его и выйти?", parent=self
            ):
                return
            self.server.stop()
        if not self.smoke:
            self._save()
        if self._drain_id is not None:
            try:
                self.after_cancel(self._drain_id)
            except tk.TclError:
                pass
        self.destroy()


def main(argv: list[str] | None = None) -> int:
    import sys

    argv = list(sys.argv[1:] if argv is None else argv)
    smoke = "--smoke" in argv
    app = App(smoke=smoke)
    app.mainloop()
    if smoke:
        try:
            print("SMOKE OK")
        except Exception:  # noqa: BLE001
            pass
    return 0
