import os
import shutil
import sys
import tempfile
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, simpledialog, ttk

from archive_utils import (
    ArchiveError,
    create_zip_archive,
    create_zip_from_directory_contents,
    extract_zip_archive,
    validate_zip_bytes,
)
from crypto import CryptoConfigurationError, WrongPasswordOrCorruptVault, decrypt_vault_data, encrypt_archive_data
from security_lockout import (
    check_lockout,
    format_blocked_until,
    record_failure,
    record_success,
    vault_lockout_id,
)
from ui import evaluate_password_strength


APP_NAME = "NOXLAB VAULT"
VAULT_EXTENSION = ".noxvault"
APP_USER_MODEL_ID = "NoxLab.Vault.App"
PROJECT_ROOT = Path(__file__).resolve().parent.parent
ICON_PATH = PROJECT_ROOT / "assets" / "noxlab_vault.ico"
ICON_PHOTO_PATH = PROJECT_ROOT / "assets" / "noxlab_vault.png"

BG = "#09090b"
PANEL = "#141417"
PANEL_2 = "#1b1b20"
RED = "#ff173d"
RED_DARK = "#8f1024"
TEXT = "#f2f2f4"
MUTED = "#aaaab3"
BORDER = "#2b2b31"
ENTRY = "#0f0f13"
TITLE_BAR = "#1a1a1d"
TITLE_BAR_BORDER = "#333338"

ASCII_HEADER = r"""
 _   _  ___  __  __ _      _    ____     __     ___    _   _ _  _____
| \ | |/ _ \ \ \/ /| |    / \  | __ )    \ \   / / \  | | | | ||_   _|
|  \| | | | | \  / | |   / _ \ |  _ \     \ \ / / _ \ | | | | |  | |
| |\  | |_| | /  \ | |__/ ___ \| |_) |     \ V / ___ \| |_| | |__| |
|_| \_|\___/ /_/\_\|____/_/   \_\____/      \_/_/   \_\\___/|____|_|
"""


class NoxLabVaultApp(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        self.title(APP_NAME)
        self._apply_window_icon()
        self._apply_dark_title_bar()
        self.protocol("WM_DELETE_WINDOW", self.on_exit)
        self.geometry("1060x740")
        self.minsize(900, 650)
        self.configure(bg=BG)

        self.selected_paths: list[Path] = []
        self.workspace_temp_dir: Path | None = None
        self.workspace_dir: Path | None = None
        self.unlocked_vault_path: Path | None = None
        self.unlocked_password = ""
        self.current_panel = ""
        self.busy = False

        self._configure_tree_style()
        self._configure_grid()
        self._build_header()
        self._build_sidebar()
        self._build_main_area()
        self._build_activity_log()
        self.show_panel("create")
        self._update_unlocked_controls()
        self.after(100, self._apply_dark_title_bar)

    def _apply_window_icon(self) -> None:
        if ICON_PATH.exists():
            try:
                self.iconbitmap(str(ICON_PATH))
                self.iconbitmap(default=str(ICON_PATH))
            except tk.TclError:
                pass

        if ICON_PHOTO_PATH.exists():
            try:
                self._icon_photo = tk.PhotoImage(file=str(ICON_PHOTO_PATH))
                self.iconphoto(True, self._icon_photo)
            except tk.TclError:
                pass

    def _apply_dark_title_bar(self) -> None:
        if sys.platform != "win32":
            return

        try:
            import ctypes

            hwnd = self.winfo_id()
            if not hwnd:
                return

            enabled = ctypes.c_int(1)
            for attribute in (20, 19):
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    ctypes.byref(enabled),
                    ctypes.sizeof(enabled),
                )

            for attribute, color in (
                (35, TITLE_BAR),
                (36, TEXT),
                (34, TITLE_BAR_BORDER),
            ):
                colorref = ctypes.c_int(_hex_to_colorref(color))
                ctypes.windll.dwmapi.DwmSetWindowAttribute(
                    hwnd,
                    attribute,
                    ctypes.byref(colorref),
                    ctypes.sizeof(colorref),
                )

            ctypes.windll.user32.SetWindowPos(
                hwnd,
                0,
                0,
                0,
                0,
                0,
                0x0001 | 0x0002 | 0x0004 | 0x0020,
            )
        except Exception:
            pass

    def _configure_grid(self) -> None:
        self.columnconfigure(0, weight=0)
        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

    def _configure_tree_style(self) -> None:
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(
            "Nox.Treeview",
            background=ENTRY,
            foreground=TEXT,
            fieldbackground=ENTRY,
            bordercolor=BORDER,
            rowheight=26,
            font=("Segoe UI", 10),
        )
        style.map(
            "Nox.Treeview",
            background=[("selected", RED_DARK)],
            foreground=[("selected", TEXT)],
        )

    def _build_header(self) -> None:
        header = tk.Frame(self, bg=BG, padx=22, pady=12)
        header.grid(row=0, column=0, columnspan=2, sticky="ew")
        header.columnconfigure(0, weight=1)

        logo = tk.Label(
            header,
            text=ASCII_HEADER,
            bg=BG,
            fg=RED,
            font=("Consolas", 9, "bold"),
            justify="left",
        )
        logo.grid(row=0, column=0, sticky="w")

        title = tk.Label(
            header,
            text="Discord: noxian_ | GitHub: noxian0",
            bg=BG,
            fg=RED,
            font=("Segoe UI", 10, "bold"),
        )
        title.grid(row=1, column=0, sticky="w", pady=(0, 2))

        warning = tk.Label(
            header,
            text="If you forget your password, the vault cannot be recovered.",
            bg=BG,
            fg=TEXT,
            font=("Segoe UI", 10),
        )
        warning.grid(row=2, column=0, sticky="w")

    def _build_sidebar(self) -> None:
        self.sidebar = tk.Frame(self, bg=PANEL, padx=12, pady=14, width=210)
        self.sidebar.grid(row=1, column=0, sticky="nsew", padx=(18, 8), pady=(0, 12))
        self.sidebar.grid_propagate(False)

        self.nav_buttons: dict[str, tk.Button] = {}
        nav_items = [
            ("create", "Create Vault"),
            ("open", "Open Vault"),
            ("verify", "Verify Vault"),
            ("notes", "Security Notes"),
        ]
        for index, (panel, label) in enumerate(nav_items):
            button = self._button(
                self.sidebar,
                label,
                command=lambda name=panel: self.show_panel(name),
                fill=True,
            )
            button.grid(row=index, column=0, sticky="ew", pady=4)
            self.nav_buttons[panel] = button

        self.sidebar.rowconfigure(len(nav_items), weight=1)
        exit_button = self._button(self.sidebar, "Exit", command=self.on_exit, fill=True, accent=False)
        exit_button.grid(row=len(nav_items) + 1, column=0, sticky="ew", pady=(18, 0))

    def _build_main_area(self) -> None:
        self.main = tk.Frame(self, bg=PANEL, padx=18, pady=18)
        self.main.grid(row=1, column=1, sticky="nsew", padx=(8, 18), pady=(0, 12))
        self.main.columnconfigure(0, weight=1)
        self.main.rowconfigure(0, weight=1)

        self.panels: dict[str, tk.Frame] = {
            "create": self._create_panel(),
            "open": self._open_panel(),
            "verify": self._verify_panel(),
            "notes": self._notes_panel(),
        }

        for panel in self.panels.values():
            panel.grid(row=0, column=0, sticky="nsew")

    def _build_activity_log(self) -> None:
        log_frame = tk.Frame(self, bg=PANEL, padx=18, pady=12)
        log_frame.grid(row=2, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 18))
        log_frame.columnconfigure(0, weight=1)

        tk.Label(
            log_frame,
            text="Activity Log",
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI", 10, "bold"),
        ).grid(row=0, column=0, sticky="w")

        self.log_list = tk.Listbox(
            log_frame,
            height=4,
            bg=ENTRY,
            fg=MUTED,
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            selectbackground=RED_DARK,
            selectforeground=TEXT,
            font=("Consolas", 9),
        )
        self.log_list.grid(row=1, column=0, sticky="ew", pady=(8, 0))

    def _create_panel(self) -> tk.Frame:
        panel = self._panel_frame()
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(2, weight=1)

        self._section_title(panel, "Create Vault", 0)

        path_bar = tk.Frame(panel, bg=PANEL)
        path_bar.grid(row=1, column=0, sticky="ew", pady=(10, 8))
        path_bar.columnconfigure(0, weight=1)

        button_row = tk.Frame(path_bar, bg=PANEL)
        button_row.grid(row=0, column=0, sticky="w")
        self._button(button_row, "Add Files", self.add_files).pack(side="left", padx=(0, 8))
        self._button(button_row, "Add Folder", self.add_folder).pack(side="left", padx=(0, 8))
        self._button(button_row, "Remove Selected", self.remove_selected_paths, accent=False).pack(
            side="left", padx=(0, 8)
        )
        self._button(button_row, "Clear", self.clear_paths, accent=False).pack(side="left")

        self.path_list = tk.Listbox(
            panel,
            height=8,
            bg=ENTRY,
            fg=TEXT,
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            selectbackground=RED_DARK,
            selectforeground=TEXT,
            font=("Segoe UI", 9),
        )
        self.path_list.grid(row=2, column=0, sticky="nsew", pady=(0, 14))

        form = tk.Frame(panel, bg=PANEL)
        form.grid(row=4, column=0, sticky="ew")
        form.columnconfigure(1, weight=1)

        self.create_save_var = tk.StringVar()
        self.create_password_var = tk.StringVar()
        self.create_confirm_var = tk.StringVar()
        self.create_password_var.trace_add("write", lambda *_: self._update_strength_label())

        self._label(form, "Save vault as").grid(row=0, column=0, sticky="w", pady=6)
        self._entry(form, self.create_save_var).grid(row=0, column=1, sticky="ew", padx=8, pady=6)
        self._button(form, "Browse", self.browse_save_vault, accent=False).grid(row=0, column=2, pady=6)

        self._label(form, "Password").grid(row=1, column=0, sticky="w", pady=6)
        self._entry(form, self.create_password_var, show="*").grid(row=1, column=1, sticky="ew", padx=8, pady=6)

        self._label(form, "Confirm").grid(row=2, column=0, sticky="w", pady=6)
        self._entry(form, self.create_confirm_var, show="*").grid(row=2, column=1, sticky="ew", padx=8, pady=6)

        self.strength_label = tk.Label(
            form,
            text="Password strength: not checked",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 9),
        )
        self.strength_label.grid(row=3, column=1, sticky="w", padx=8, pady=(0, 8))

        warning = tk.Label(
            panel,
            text="Warning: if you forget this password, the vault cannot be recovered.",
            bg=PANEL,
            fg=RED,
            font=("Segoe UI", 10, "bold"),
        )
        warning.grid(row=5, column=0, sticky="w", pady=(12, 8))

        self.create_button = self._button(panel, "Create Encrypted Vault", self.create_vault)
        self.create_button.grid(row=6, column=0, sticky="ew", pady=(4, 0))
        return panel

    def _open_panel(self) -> tk.Frame:
        panel = self._panel_frame()
        panel.columnconfigure(0, weight=1)
        panel.rowconfigure(4, weight=1)
        self._section_title(panel, "Open / Edit Vault", 0)

        form = tk.Frame(panel, bg=PANEL)
        form.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        form.columnconfigure(1, weight=1)

        self.open_vault_var = tk.StringVar()
        self.open_password_var = tk.StringVar()
        self.unlock_status_var = tk.StringVar(value="No vault unlocked.")

        self._label(form, "Vault file").grid(row=0, column=0, sticky="w", pady=8)
        self._entry(form, self.open_vault_var).grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        self._button(form, "Browse", self.browse_open_vault, accent=False).grid(row=0, column=2, pady=8)

        self._label(form, "Password").grid(row=1, column=0, sticky="w", pady=8)
        self._entry(form, self.open_password_var, show="*").grid(row=1, column=1, sticky="ew", padx=8, pady=8)

        self.open_button = self._button(form, "Unlock Vault", self.open_vault)
        self.open_button.grid(row=2, column=1, sticky="ew", padx=8, pady=(10, 4))

        status = tk.Label(
            panel,
            textvariable=self.unlock_status_var,
            bg=PANEL,
            fg=RED,
            font=("Segoe UI", 10, "bold"),
        )
        status.grid(row=2, column=0, sticky="w", pady=(16, 8))

        tool_row = tk.Frame(panel, bg=PANEL)
        tool_row.grid(row=3, column=0, sticky="ew", pady=(0, 8))
        self.open_selected_button = self._button(tool_row, "Open Selected", self.open_selected_workspace_item)
        self.open_selected_button.pack(side="left", padx=(0, 8))
        self.open_workspace_button = self._button(tool_row, "Open Workspace Folder", self.open_workspace_folder, accent=False)
        self.open_workspace_button.pack(side="left", padx=(0, 8))
        self.add_workspace_files_button = self._button(tool_row, "Add Files", self.add_files_to_workspace, accent=False)
        self.add_workspace_files_button.pack(side="left", padx=(0, 8))
        self.add_workspace_folder_button = self._button(tool_row, "Add Folder", self.add_folder_to_workspace, accent=False)
        self.add_workspace_folder_button.pack(side="left", padx=(0, 8))
        self.new_folder_button = self._button(tool_row, "New Folder", self.new_workspace_folder, accent=False)
        self.new_folder_button.pack(side="left", padx=(0, 8))
        self.delete_selected_button = self._button(tool_row, "Delete", self.delete_selected_workspace_item, accent=False)
        self.delete_selected_button.pack(side="left", padx=(0, 8))
        self.refresh_tree_button = self._button(tool_row, "Refresh", self.refresh_workspace_tree, accent=False)
        self.refresh_tree_button.pack(side="left")

        tree_frame = tk.Frame(panel, bg=PANEL)
        tree_frame.grid(row=4, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.workspace_tree = ttk.Treeview(tree_frame, show="tree", style="Nox.Treeview")
        self.workspace_tree.grid(row=0, column=0, sticky="nsew")
        self.workspace_tree.bind("<Double-1>", lambda _event: self.open_selected_workspace_item())

        scrollbar = tk.Scrollbar(tree_frame, command=self.workspace_tree.yview, bg=PANEL_2, troughcolor=ENTRY)
        scrollbar.grid(row=0, column=1, sticky="ns")
        self.workspace_tree.configure(yscrollcommand=scrollbar.set)

        lock_row = tk.Frame(panel, bg=PANEL)
        lock_row.grid(row=5, column=0, sticky="ew", pady=(12, 0))
        lock_row.columnconfigure(0, weight=1)
        lock_row.columnconfigure(1, weight=1)
        self.lock_save_button = self._button(lock_row, "Lock & Save Changes", self.lock_and_save_vault)
        self.lock_save_button.grid(row=0, column=0, sticky="ew", padx=(0, 8))
        self.discard_button = self._button(lock_row, "Discard & Close", self.discard_unlocked_vault, accent=False)
        self.discard_button.grid(row=0, column=1, sticky="ew", padx=(8, 0))
        return panel

    def _verify_panel(self) -> tk.Frame:
        panel = self._panel_frame()
        panel.columnconfigure(0, weight=1)
        self._section_title(panel, "Verify Vault", 0)

        form = tk.Frame(panel, bg=PANEL)
        form.grid(row=1, column=0, sticky="ew", pady=(16, 0))
        form.columnconfigure(1, weight=1)

        self.verify_vault_var = tk.StringVar()
        self.verify_password_var = tk.StringVar()

        self._label(form, "Vault file").grid(row=0, column=0, sticky="w", pady=8)
        self._entry(form, self.verify_vault_var).grid(row=0, column=1, sticky="ew", padx=8, pady=8)
        self._button(form, "Browse", self.browse_verify_vault, accent=False).grid(row=0, column=2, pady=8)

        self._label(form, "Password").grid(row=1, column=0, sticky="w", pady=8)
        self._entry(form, self.verify_password_var, show="*").grid(row=1, column=1, sticky="ew", padx=8, pady=8)

        info = tk.Label(
            panel,
            text="Verification decrypts and checks the archive in memory. It does not extract files.",
            bg=PANEL,
            fg=MUTED,
            font=("Segoe UI", 10),
        )
        info.grid(row=2, column=0, sticky="w", pady=(14, 6))

        self.verify_button = self._button(panel, "Verify Password and Vault", self.verify_vault)
        self.verify_button.grid(row=3, column=0, sticky="ew", pady=(8, 0))
        return panel

    def _notes_panel(self) -> tk.Frame:
        panel = self._panel_frame()
        panel.columnconfigure(0, weight=1)
        self._section_title(panel, "About / Security Notes", 0)

        notes = (
            "NOXLAB VAULT is local only. Nothing is uploaded.\n\n"
            "Vault data is encrypted with AES-256-GCM. Argon2id is used for password key "
            "derivation when available; PBKDF2-HMAC-SHA256 is used as a fallback.\n\n"
            "The whole ZIP archive is encrypted as one blob, so filenames, folder names, "
            "and file contents are hidden without the password.\n\n"
            "When a vault is unlocked for editing, its contents are temporarily decrypted "
            "on this PC so normal apps can open and modify the files. Lock & Save Changes "
            "re-encrypts the updated workspace back into the vault and cleans the temporary files.\n\n"
            "After 5 wrong password or corrupted-vault failures for the same vault identity, "
            "Open and Verify are blocked for 5 hours. The timer is stored locally and survives "
            "closing and reopening the app.\n\n"
            "Forgotten passwords cannot be recovered. There is no backdoor, recovery key, "
            "or account reset.\n\n"
            "Weak passwords can be guessed. Use 16+ characters or a long passphrase.\n\n"
            "Malware on this PC can still access files while the vault is unlocked. "
            "Do not store the password next to the vault file."
        )

        tk.Label(
            panel,
            text=notes,
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI", 11),
            justify="left",
            wraplength=720,
        ).grid(row=1, column=0, sticky="nw", pady=(16, 0))
        return panel

    def show_panel(self, panel_name: str) -> None:
        self.current_panel = panel_name
        self.panels[panel_name].tkraise()
        for name, button in self.nav_buttons.items():
            button.configure(bg=RED if name == panel_name else PANEL_2)

    def on_exit(self) -> None:
        if self.workspace_dir is not None:
            result = messagebox.askyesnocancel(
                "Vault is unlocked",
                "Save changes and lock the vault before exiting?\n\n"
                "Yes saves changes. No discards changes. Cancel keeps the app open.",
            )
            if result is None:
                return
            if result:
                if not self.lock_and_save_vault(ask_confirmation=False):
                    return
            else:
                if not self.discard_unlocked_vault(ask_confirmation=False):
                    return

        self.destroy()

    def add_files(self) -> None:
        paths = filedialog.askopenfilenames(title="Select files to protect")
        self._add_selected_paths(paths)

    def add_folder(self) -> None:
        path = filedialog.askdirectory(title="Select folder to protect")
        if path:
            self._add_selected_paths([path])

    def remove_selected_paths(self) -> None:
        selected = list(self.path_list.curselection())
        selected.reverse()
        for index in selected:
            del self.selected_paths[index]
        self._refresh_path_list()

    def clear_paths(self) -> None:
        self.selected_paths.clear()
        self._refresh_path_list()

    def browse_save_vault(self) -> None:
        path = filedialog.asksaveasfilename(
            title="Save vault",
            defaultextension=VAULT_EXTENSION,
            filetypes=[("NOXLAB vault", f"*{VAULT_EXTENSION}"), ("All files", "*.*")],
        )
        if path:
            self.create_save_var.set(path)

    def browse_open_vault(self) -> None:
        path = self._browse_vault_file()
        if path:
            self.open_vault_var.set(path)

    def browse_verify_vault(self) -> None:
        path = self._browse_vault_file()
        if path:
            self.verify_vault_var.set(path)

    def create_vault(self) -> None:
        if self.busy:
            return

        password = self.create_password_var.get()
        confirmation = self.create_confirm_var.get()
        try:
            if not self.selected_paths:
                raise ValueError("Select at least one file or folder.")
            vault_path = self._normalize_vault_path(self.create_save_var.get(), must_exist=False)
            if password != confirmation:
                raise ValueError("Passwords do not match.")
            if not password:
                raise ValueError("Password must not be empty.")

            strength, warnings = evaluate_password_strength(password)
            if strength == "weak":
                warning_text = "Weak passwords reduce vault security.\n\n" + "\n".join(warnings)
                if not messagebox.askyesno("Weak password", f"{warning_text}\n\nContinue anyway?"):
                    return

            if vault_path.exists() and not messagebox.askyesno(
                "Overwrite vault", "A vault file already exists at that location. Overwrite it?"
            ):
                return

            if not messagebox.askyesno(
                "Password warning",
                "If you forget this password, the vault cannot be recovered.\n\nCreate encrypted vault now?",
            ):
                return

            self._set_busy(True)
            self._log("creating temporary archive")
            temp_dir: Path | None = None
            try:
                temp_dir = Path(tempfile.mkdtemp(prefix="noxvault_create_"))
                archive_path = temp_dir / "payload.zip"
                stats = create_zip_archive(self.selected_paths, archive_path)

                self._log("encrypting archive")
                archive_data = archive_path.read_bytes()
                vault_data = encrypt_archive_data(archive_data, password)
                del archive_data

                archive_path.unlink(missing_ok=True)
                vault_path.parent.mkdir(parents=True, exist_ok=True)
                vault_path.write_bytes(vault_data)

                self._log("vault created")
                messagebox.showinfo(
                    "Vault created",
                    f"Vault created successfully.\n\nProtected {stats.files} file(s).",
                )
            finally:
                self._cleanup_temp_dir(temp_dir)
        except (ArchiveError, OSError, ValueError) as exc:
            messagebox.showerror("Create failed", str(exc))
        except CryptoConfigurationError as exc:
            messagebox.showerror("Crypto setup error", str(exc))
        finally:
            self._set_busy(False)
            password = ""
            confirmation = ""

    def open_vault(self) -> None:
        if self.busy:
            return

        if self.workspace_dir is not None:
            messagebox.showinfo("Vault already unlocked", "Lock or discard the current vault before opening another one.")
            return

        password = self.open_password_var.get()
        temp_dir: Path | None = None
        vault_id: str | None = None
        try:
            vault_path = self._normalize_vault_path(self.open_vault_var.get(), must_exist=True)
            if not password:
                raise ValueError("Password is required.")

            self._set_busy(True)
            self._log("decrypting vault")
            vault_data = vault_path.read_bytes()
            vault_id = vault_lockout_id(vault_data)
            lockout_status = check_lockout(vault_id)
            if lockout_status.blocked:
                raise VaultLockedOutError(lockout_status.blocked_until)

            archive_data = decrypt_vault_data(vault_data, password)
            validate_zip_bytes(archive_data)
            record_success(vault_id)

            temp_dir = Path(tempfile.mkdtemp(prefix="noxvault_extract_"))
            workspace_dir = temp_dir / "workspace"
            workspace_dir.mkdir()
            archive_path = temp_dir / "payload.zip"
            archive_path.write_bytes(archive_data)
            del archive_data

            self._log("opening editable workspace")
            extract_zip_archive(archive_path, workspace_dir, overwrite=False)
            archive_path.unlink(missing_ok=True)

            self.workspace_temp_dir = temp_dir
            self.workspace_dir = workspace_dir
            self.unlocked_vault_path = vault_path
            self.unlocked_password = password
            temp_dir = None

            self.open_password_var.set("")
            self.unlock_status_var.set(f"Unlocked: {vault_path.name}")
            self.refresh_workspace_tree()
            self._update_unlocked_controls()
            self._log("vault unlocked")
            messagebox.showinfo(
                "Vault unlocked",
                "Vault unlocked for editing.\n\nOpen files from the list, save your edits in the editor, then use Lock & Save Changes.",
            )
        except WrongPasswordOrCorruptVault:
            if vault_id is not None:
                failure_status = record_failure(vault_id)
                if failure_status.blocked:
                    self._log("vault locked after failed attempts")
                    messagebox.showerror(
                        "Open blocked",
                        "Wrong password or corrupted vault.\n\n"
                        f"Too many failed attempts. Open and Verify are blocked for this vault until "
                        f"{format_blocked_until(failure_status.blocked_until)}.",
                    )
                    return

            self._log("wrong password/corrupt vault")
            message = "Wrong password or corrupted vault."
            if vault_id is not None:
                message += f"\n\nAttempts remaining before 5-hour block: {failure_status.attempts_remaining}"
            messagebox.showerror("Open failed", message)
        except VaultLockedOutError as exc:
            self._log("vault unlock blocked")
            messagebox.showerror(
                "Open blocked",
                f"Too many failed attempts. Open and Verify are blocked for this vault until "
                f"{format_blocked_until(exc.blocked_until)}.",
            )
        except CryptoConfigurationError as exc:
            messagebox.showerror("Crypto setup error", str(exc))
        except (ArchiveError, OSError, ValueError) as exc:
            messagebox.showerror("Open failed", str(exc))
        finally:
            self._cleanup_temp_dir(temp_dir)
            self._set_busy(False)
            password = ""

    def lock_and_save_vault(self, *, ask_confirmation: bool = True) -> bool:
        if self.busy:
            return False

        if self.workspace_dir is None or self.workspace_temp_dir is None or self.unlocked_vault_path is None:
            messagebox.showinfo("No unlocked vault", "Open a vault before saving changes.")
            return False

        if ask_confirmation and not messagebox.askyesno(
            "Lock and save",
            "Save all file edits in other apps before locking.\n\nRe-encrypt the workspace and save it back into the vault?",
        ):
            return False

        save_temp_dir: Path | None = None
        replacement_path: Path | None = None
        try:
            self._set_busy(True)
            self._log("building updated archive")
            save_temp_dir = Path(tempfile.mkdtemp(prefix="noxvault_save_"))
            archive_path = save_temp_dir / "payload.zip"
            stats = create_zip_from_directory_contents(self.workspace_dir, archive_path)

            self._log("encrypting updated vault")
            archive_data = archive_path.read_bytes()
            vault_data = encrypt_archive_data(archive_data, self.unlocked_password)
            del archive_data

            with tempfile.NamedTemporaryFile(
                prefix=f"{self.unlocked_vault_path.name}.",
                suffix=".tmp",
                dir=self.unlocked_vault_path.parent,
                delete=False,
            ) as handle:
                replacement_path = Path(handle.name)
                handle.write(vault_data)

            os.replace(replacement_path, self.unlocked_vault_path)
            replacement_path = None

            self._log("vault saved")
            messagebox.showinfo(
                "Vault saved",
                f"Changes saved and vault locked.\n\nStored {stats.files} file(s).",
            )
            self._close_unlocked_workspace()
            return True
        except (ArchiveError, OSError, ValueError) as exc:
            messagebox.showerror("Save failed", str(exc))
            return False
        except CryptoConfigurationError as exc:
            messagebox.showerror("Crypto setup error", str(exc))
            return False
        finally:
            if replacement_path is not None:
                replacement_path.unlink(missing_ok=True)
            self._cleanup_temp_dir(save_temp_dir)
            self._set_busy(False)

    def discard_unlocked_vault(self, *, ask_confirmation: bool = True) -> bool:
        if self.workspace_dir is None:
            return True

        if ask_confirmation and not messagebox.askyesno(
            "Discard changes",
            "Discard unlocked files and close this vault without saving changes?",
        ):
            return False

        self._close_unlocked_workspace()
        self._log("unlocked changes discarded")
        return True

    def open_selected_workspace_item(self) -> None:
        try:
            path = self._selected_workspace_path()
            os.startfile(str(path))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Open failed", str(exc))

    def open_workspace_folder(self) -> None:
        try:
            if self.workspace_dir is None:
                raise ValueError("No vault is unlocked.")
            os.startfile(str(self.workspace_dir))
        except (OSError, ValueError) as exc:
            messagebox.showerror("Open failed", str(exc))

    def add_files_to_workspace(self) -> None:
        if self.workspace_dir is None:
            return
        paths = filedialog.askopenfilenames(title="Add files to unlocked vault")
        if paths:
            self._copy_paths_into_workspace([Path(path) for path in paths])

    def add_folder_to_workspace(self) -> None:
        if self.workspace_dir is None:
            return
        path = filedialog.askdirectory(title="Add folder to unlocked vault")
        if path:
            self._copy_paths_into_workspace([Path(path)])

    def new_workspace_folder(self) -> None:
        if self.workspace_dir is None:
            return

        name = simpledialog.askstring("New folder", "Folder name:")
        if name is None:
            return
        name = name.strip()
        if not name or any(char in name for char in '<>:"/\\|?*') or name in {".", ".."}:
            messagebox.showerror("Invalid name", "Use a normal folder name without path characters.")
            return

        target_parent = self.workspace_dir
        selection = self.workspace_tree.selection()
        if selection:
            selected = Path(selection[0])
            if selected.is_dir():
                target_parent = selected
            else:
                target_parent = selected.parent

        target = (target_parent / name).resolve()
        try:
            self._ensure_workspace_child(target)
            if target.exists():
                raise ValueError("A folder or file with that name already exists.")
            target.mkdir()
            self.refresh_workspace_tree()
            self._log("folder created")
        except (OSError, ValueError) as exc:
            messagebox.showerror("New folder failed", str(exc))

    def delete_selected_workspace_item(self) -> None:
        try:
            path = self._selected_workspace_path()
            if not messagebox.askyesno("Delete item", f"Delete '{path.name}' from the unlocked vault workspace?"):
                return

            if path.is_dir():
                shutil.rmtree(path)
            else:
                path.unlink()
            self.refresh_workspace_tree()
            self._log("workspace item deleted")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Delete failed", str(exc))

    def refresh_workspace_tree(self) -> None:
        self.workspace_tree.delete(*self.workspace_tree.get_children())
        if self.workspace_dir is None or not self.workspace_dir.exists():
            return

        for child in self._sorted_workspace_children(self.workspace_dir):
            self._add_workspace_tree_node(child, "")

    def verify_vault(self) -> None:
        if self.busy:
            return

        password = self.verify_password_var.get()
        vault_id: str | None = None
        try:
            vault_path = self._normalize_vault_path(self.verify_vault_var.get(), must_exist=True)
            if not password:
                raise ValueError("Password is required.")

            self._set_busy(True)
            self._log("verifying vault")
            vault_data = vault_path.read_bytes()
            vault_id = vault_lockout_id(vault_data)
            lockout_status = check_lockout(vault_id)
            if lockout_status.blocked:
                raise VaultLockedOutError(lockout_status.blocked_until)

            archive_data = decrypt_vault_data(vault_data, password)
            validate_zip_bytes(archive_data)
            record_success(vault_id)

            self._log("vault verified")
            messagebox.showinfo("Vault verified", "Vault verified successfully. No files were extracted.")
        except WrongPasswordOrCorruptVault:
            if vault_id is not None:
                failure_status = record_failure(vault_id)
                if failure_status.blocked:
                    self._log("vault locked after failed attempts")
                    messagebox.showerror(
                        "Verify blocked",
                        "Wrong password or corrupted vault.\n\n"
                        f"Too many failed attempts. Open and Verify are blocked for this vault until "
                        f"{format_blocked_until(failure_status.blocked_until)}.",
                    )
                    return

            self._log("wrong password/corrupt vault")
            message = "Wrong password or corrupted vault."
            if vault_id is not None:
                message += f"\n\nAttempts remaining before 5-hour block: {failure_status.attempts_remaining}"
            messagebox.showerror("Verify failed", message)
        except VaultLockedOutError as exc:
            self._log("vault verify blocked")
            messagebox.showerror(
                "Verify blocked",
                f"Too many failed attempts. Open and Verify are blocked for this vault until "
                f"{format_blocked_until(exc.blocked_until)}.",
            )
        except CryptoConfigurationError as exc:
            messagebox.showerror("Crypto setup error", str(exc))
        except (ArchiveError, OSError, ValueError) as exc:
            messagebox.showerror("Verify failed", str(exc))
        finally:
            self._set_busy(False)
            password = ""

    def _add_selected_paths(self, paths: list[str] | tuple[str, ...]) -> None:
        existing = {path.resolve() for path in self.selected_paths}
        for raw_path in paths:
            path = Path(raw_path).expanduser().resolve()
            if path.exists() and path not in existing:
                self.selected_paths.append(path)
                existing.add(path)
        self._refresh_path_list()

    def _refresh_path_list(self) -> None:
        self.path_list.delete(0, tk.END)
        for path in self.selected_paths:
            self.path_list.insert(tk.END, str(path))

    def _copy_paths_into_workspace(self, paths: list[Path]) -> None:
        if self.workspace_dir is None:
            return

        copied = 0
        try:
            for source in paths:
                source = source.expanduser().resolve()
                if not source.exists():
                    continue

                target = (self.workspace_dir / source.name).resolve()
                self._ensure_workspace_child(target)

                if source == target:
                    continue

                if target.exists():
                    if not messagebox.askyesno("Replace item", f"'{target.name}' already exists. Replace it?"):
                        continue
                    self._remove_workspace_path(target)

                if source.is_dir():
                    shutil.copytree(source, target)
                elif source.is_file():
                    shutil.copy2(source, target)
                copied += 1

            if copied:
                self.refresh_workspace_tree()
                self._log("workspace items added")
        except (OSError, ValueError) as exc:
            messagebox.showerror("Add failed", str(exc))

    def _selected_workspace_path(self) -> Path:
        selection = self.workspace_tree.selection()
        if not selection:
            raise ValueError("Select a file or folder first.")

        path = Path(selection[0]).resolve()
        self._ensure_workspace_child(path)
        if not path.exists():
            raise ValueError("Selected item no longer exists.")
        return path

    def _ensure_workspace_child(self, path: Path) -> None:
        if self.workspace_dir is None:
            raise ValueError("No vault is unlocked.")

        workspace = self.workspace_dir.resolve()
        try:
            path.resolve().relative_to(workspace)
        except ValueError as exc:
            raise ValueError("Path is outside the unlocked vault workspace.") from exc

    def _remove_workspace_path(self, path: Path) -> None:
        self._ensure_workspace_child(path)
        if path.is_dir():
            shutil.rmtree(path)
        else:
            path.unlink()

    def _sorted_workspace_children(self, folder: Path) -> list[Path]:
        return sorted(folder.iterdir(), key=lambda path: (not path.is_dir(), path.name.lower()))

    def _add_workspace_tree_node(self, path: Path, parent: str) -> None:
        label = f"{path.name}/" if path.is_dir() else path.name
        item_id = str(path.resolve())
        self.workspace_tree.insert(parent, "end", iid=item_id, text=label, open=False)

        if path.is_dir():
            for child in self._sorted_workspace_children(path):
                self._add_workspace_tree_node(child, item_id)

    def _close_unlocked_workspace(self) -> None:
        temp_dir = self.workspace_temp_dir
        self.workspace_temp_dir = None
        self.workspace_dir = None
        self.unlocked_vault_path = None
        self.unlocked_password = ""
        self.unlock_status_var.set("No vault unlocked.")
        self.workspace_tree.delete(*self.workspace_tree.get_children())
        self._cleanup_temp_dir(temp_dir)
        self._update_unlocked_controls()

    def _browse_vault_file(self) -> str:
        return filedialog.askopenfilename(
            title="Select vault",
            filetypes=[("NOXLAB vault", f"*{VAULT_EXTENSION}"), ("All files", "*.*")],
        )

    def _update_strength_label(self) -> None:
        password = self.create_password_var.get()
        if not password:
            self.strength_label.configure(text="Password strength: not checked", fg=MUTED)
            return

        strength, warnings = evaluate_password_strength(password)
        color = RED if strength == "weak" else "#ffc857" if strength == "usable" else "#54d17a"
        extra = f" - {warnings[0]}" if warnings else ""
        self.strength_label.configure(text=f"Password strength: {strength}{extra}", fg=color)

    def _normalize_vault_path(self, value: str, *, must_exist: bool) -> Path:
        if not value.strip():
            raise ValueError("Vault path is required.")

        path = Path(value.strip().strip('"')).expanduser()
        if path.suffix.lower() != VAULT_EXTENSION:
            path = path.with_suffix(VAULT_EXTENSION)
        path = path.resolve()

        if must_exist and not path.is_file():
            raise ValueError("Vault file does not exist.")
        return path

    def _cleanup_temp_dir(self, temp_dir: Path | None) -> None:
        if temp_dir is None:
            return
        try:
            shutil.rmtree(temp_dir)
            self._log("temporary files cleaned")
        except OSError:
            messagebox.showwarning("Cleanup warning", f"Temporary files could not be cleaned:\n{temp_dir}")

    def _set_busy(self, busy: bool) -> None:
        self.busy = busy
        self._update_unlocked_controls()
        self.update_idletasks()

    def _update_unlocked_controls(self) -> None:
        if not hasattr(self, "open_button"):
            return

        unlocked = self.workspace_dir is not None
        normal = tk.NORMAL
        disabled = tk.DISABLED

        self.create_button.configure(state=disabled if self.busy else normal)
        self.verify_button.configure(state=disabled if self.busy else normal)
        self.open_button.configure(state=disabled if self.busy or unlocked else normal)

        workspace_state = normal if unlocked and not self.busy else disabled
        for button in (
            self.open_selected_button,
            self.open_workspace_button,
            self.add_workspace_files_button,
            self.add_workspace_folder_button,
            self.new_folder_button,
            self.delete_selected_button,
            self.refresh_tree_button,
            self.lock_save_button,
            self.discard_button,
        ):
            button.configure(state=workspace_state)

    def _log(self, message: str) -> None:
        timestamp = datetime.now().strftime("%H:%M:%S")
        self.log_list.insert(tk.END, f"{timestamp} - {message}")
        self.log_list.yview_moveto(1)

    def _panel_frame(self) -> tk.Frame:
        return tk.Frame(self.main, bg=PANEL)

    def _section_title(self, parent: tk.Widget, text: str, row: int) -> None:
        tk.Label(
            parent,
            text=text,
            bg=PANEL,
            fg=TEXT,
            font=("Segoe UI", 18, "bold"),
        ).grid(row=row, column=0, sticky="w")

    def _label(self, parent: tk.Widget, text: str) -> tk.Label:
        return tk.Label(parent, text=text, bg=PANEL, fg=MUTED, font=("Segoe UI", 10, "bold"))

    def _entry(self, parent: tk.Widget, variable: tk.StringVar, *, show: str | None = None) -> tk.Entry:
        return tk.Entry(
            parent,
            textvariable=variable,
            show=show,
            bg=ENTRY,
            fg=TEXT,
            insertbackground=TEXT,
            relief="flat",
            bd=0,
            highlightthickness=1,
            highlightbackground=BORDER,
            highlightcolor=RED,
            font=("Segoe UI", 10),
        )

    def _button(
        self,
        parent: tk.Widget,
        text: str,
        command,
        *,
        fill: bool = False,
        accent: bool = True,
    ) -> tk.Button:
        button = tk.Button(
            parent,
            text=text,
            command=command,
            bg=RED if accent else PANEL_2,
            fg=TEXT,
            activebackground=RED_DARK if accent else BORDER,
            activeforeground=TEXT,
            bd=0,
            relief="flat",
            padx=14,
            pady=10,
            cursor="hand2",
            font=("Segoe UI", 10, "bold"),
        )
        if fill:
            button.configure(anchor="w")
        return button


def run_gui() -> None:
    _set_windows_app_id()
    app = NoxLabVaultApp()
    app.mainloop()


class VaultLockedOutError(Exception):
    def __init__(self, blocked_until: float | None) -> None:
        super().__init__("Vault is locked out after too many failed attempts.")
        self.blocked_until = blocked_until


def _hex_to_colorref(hex_color: str) -> int:
    color = hex_color.lstrip("#")
    red = int(color[0:2], 16)
    green = int(color[2:4], 16)
    blue = int(color[4:6], 16)
    return red | (green << 8) | (blue << 16)


def _set_windows_app_id() -> None:
    if sys.platform != "win32":
        return
    try:
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(APP_USER_MODEL_ID)
    except Exception:
        pass


if __name__ == "__main__":
    run_gui()
