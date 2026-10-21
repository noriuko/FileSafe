import io
import os
import re
import sys
import json
import uuid
import time
import math
import queue
import threading
from pathlib import Path
from tkinter import filedialog, messagebox
from PIL import Image, UnidentifiedImageError
import customtkinter as ctk

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    HAS_DND = True
except ImportError:
    HAS_DND = False

from crypto_engine import (
    encrypt_file,
    decrypt_file,
    decrypt_to_memory,
    DecryptionError,
    HEADER_SIZE,
)
from shredder import shred_file, FileLockedError, ShredderError, SSD_WEAR_LEVELING_WARNING

# UI & Security Constants
INACTIVITY_TIMEOUT_SECONDS = 300  # 5 minutes
ENCRYPTED_EXT = ".fsafe"

TEXT_EXTENSIONS = {
    ".txt", ".md", ".py", ".json", ".csv", ".log", ".xml", ".yaml", ".yml",
    ".ini", ".cfg", ".conf", ".html", ".css", ".js", ".ts", ".c", ".cpp", ".h",
    ".sql", ".sh", ".bat", ".ps1",
}
IMAGE_EXTENSIONS = {".png", ".jpg", ".jpeg", ".bmp", ".gif", ".webp", ".ico", ".tiff"}


def get_app_base_dir() -> Path:
    """Returns the directory containing FileSafe.exe (when frozen) or app.py."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


VAULT_DIR = get_app_base_dir() / "Vault"
INDEX_FILE = VAULT_DIR / "vault_index.fsafe"


class BaseWindow(ctk.CTk, TkinterDnD.DnDWrapper if HAS_DND else object):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if HAS_DND:
            self.TkdndVersion = TkinterDnD._require(self)


def calculate_password_strength(password: str) -> tuple[float, str, str]:
    if not password:
        return 0.0, "Empty", "#555555"

    pool = 0
    if re.search(r"[a-z]", password):
        pool += 26
    if re.search(r"[A-Z]", password):
        pool += 26
    if re.search(r"\d", password):
        pool += 10
    if re.search(r"[^a-zA-Z0-9]", password):
        pool += 32

    entropy = len(password) * math.log2(max(pool, 1))
    score = min(entropy / 100.0, 1.0)

    if entropy < 40:
        return score, "Weak", "#e74c3c"
    elif entropy < 65:
        return score, "Moderate", "#f39c12"
    elif entropy < 85:
        return score, "Strong", "#2ecc71"
    return 1.0, "Very Strong (High Entropy)", "#00bc8c"


def format_size(num_bytes: int) -> str:
    for unit in ["B", "KB", "MB", "GB", "TB"]:
        if num_bytes < 1024.0:
            return f"{num_bytes:.1f} {unit}"
        num_bytes /= 1024.0
    return f"{num_bytes:.1f} PB"


class InMemoryPreviewModal(ctk.CTkToplevel):
    """
    Displays decrypted text or images strictly in RAM using io.BytesIO.
    Explicitly zeroes the underlying bytearray buffer when closed or auto-locked.
    """
    def __init__(self, parent: "FileSafeApp", filename: str, raw_buffer: bytearray):
        super().__init__(parent)
        self.parent_app = parent
        self.filename = filename
        self.raw_buffer = raw_buffer
        self._pil_image: Image.Image | None = None
        self._ctk_image: ctk.CTkImage | None = None
        self._bytes_io: io.BytesIO | None = None
        self._textbox: ctk.CTkTextbox | None = None

        self.title(f"👁 In-Memory Preview — {filename} (RAM Only, Never Written to Disk)")
        self.geometry("760x580")
        self.minsize(520, 400)

        # Ensure modal stays on top and scrubs RAM on close
        self.transient(parent)
        self.protocol("WM_DELETE_WINDOW", self.close_and_scrub)

        # Bind activity inside modal to parent's inactivity watchdog
        for event_seq in ("<Motion>", "<KeyPress>", "<ButtonPress>", "<MouseWheel>"):
            self.bind(event_seq, self.parent_app._record_user_activity, add="+")

        self._build_ui()

    def _build_ui(self):
        top_banner = ctk.CTkFrame(self, height=42, corner_radius=0, fg_color="gray18")
        top_banner.pack(fill="x")

        ctk.CTkLabel(
            top_banner,
            text=f"🔒 Viewing in RAM: {self.filename} ({format_size(len(self.raw_buffer))})",
            font=ctk.CTkFont(size=13, weight="bold"),
        ).pack(side="left", padx=16, pady=8)

        ctk.CTkButton(
            top_banner,
            text="Close & Wipe RAM",
            width=130,
            height=28,
            fg_color="#c0392b",
            hover_color="#922b21",
            command=self.close_and_scrub,
        ).pack(side="right", padx=16, pady=8)

        ext = Path(self.filename).suffix.lower()

        if ext in IMAGE_EXTENSIONS:
            self._render_image()
        else:
            self._render_text(ext)

    def _render_image(self):
        try:
            self._bytes_io = io.BytesIO(self.raw_buffer)
            self._pil_image = Image.open(self._bytes_io)
            self._pil_image.load()  # Decode pixel data into memory

            # Fit image within 700x480 bounding box while preserving aspect ratio
            max_w, max_h = 700, 480
            img_w, img_h = self._pil_image.size
            scale = min(max_w / max(img_w, 1), max_h / max(img_h, 1), 1.0)
            disp_size = (max(1, int(img_w * scale)), max(1, int(img_h * scale)))

            self._ctk_image = ctk.CTkImage(
                light_image=self._pil_image,
                dark_image=self._pil_image,
                size=disp_size,
            )

            img_frame = ctk.CTkScrollableFrame(self, corner_radius=6)
            img_frame.pack(fill="both", expand=True, padx=16, pady=16)

            lbl = ctk.CTkLabel(img_frame, text="", image=self._ctk_image)
            lbl.pack(expand=True, pady=10)

        except (UnidentifiedImageError, OSError) as exc:
            self._show_fallback_notice(f"Could not decode image stream in memory:\n{exc}")

    def _render_text(self, ext: str):
        try:
            text_content = self.raw_buffer.decode("utf-8")
        except UnicodeDecodeError:
            if ext in TEXT_EXTENSIONS:
                text_content = self.raw_buffer.decode("latin-1", errors="replace")
            else:
                self._show_fallback_notice(
                    f"'{self.filename}' is a binary file ({format_size(len(self.raw_buffer))}).\n"
                    "In-memory preview supports UTF-8 text/code files and standard image formats."
                )
                return

        self._textbox = ctk.CTkTextbox(
            self,
            font=ctk.CTkFont(family="Consolas", size=13),
            wrap="word",
            corner_radius=6,
        )
        self._textbox.pack(fill="both", expand=True, padx=16, pady=16)
        self._textbox.insert("1.0", text_content)
        self._textbox.configure(state="disabled")  # Read-only view
        del text_content

    def _show_fallback_notice(self, message: str):
        lbl = ctk.CTkLabel(
            self,
            text=message,
            font=ctk.CTkFont(size=14),
            text_color="gray75",
            justify="center",
        )
        lbl.pack(expand=True, padx=30, pady=30)

    def close_and_scrub(self):
        """Zeroes out the in-memory bytearray and clears widget buffers before closing."""
        if self._textbox is not None:
            self._textbox.configure(state="normal")
            self._textbox.delete("1.0", "end")
            self._textbox = None

        if self._pil_image is not None:
            self._pil_image.close()
            self._pil_image = None

        if self._bytes_io is not None:
            self._bytes_io.close()
            self._bytes_io = None

        self._ctk_image = None

        if self.raw_buffer is not None:
            for i in range(len(self.raw_buffer)):
                self.raw_buffer[i] = 0
            self.raw_buffer.clear()

        if self in self.parent_app.active_previews:
            self.parent_app.active_previews.remove(self)

        self.destroy()


class FileSafeApp(BaseWindow):
    def __init__(self):
        super().__init__()
        VAULT_DIR.mkdir(parents=True, exist_ok=True)

        ctk.set_appearance_mode("Dark")
        ctk.set_default_color_theme("blue")

        self.title("File Safe — AES-256-GCM Vault")
        self.geometry("980x660")
        self.minsize(880, 580)

        self._session_secret: bytearray | None = None
        self._last_activity_ts: float = time.monotonic()
        self._is_unlocked: bool = False
        self._worker_busy: bool = False

        self.vault_index: dict[str, dict] = {}
        self.pending_files: list[Path] = []
        self.table_rows: dict[str, dict] = {}
        self.active_previews: list[InMemoryPreviewModal] = []
        self.ui_event_queue: queue.Queue = queue.Queue()

        for event_seq in ("<Motion>", "<KeyPress>", "<ButtonPress>", "<MouseWheel>"):
            self.bind_all(event_seq, self._record_user_activity, add="+")

        self.unlock_frame = ctk.CTkFrame(self, corner_radius=0)
        self.dashboard_frame = ctk.CTkFrame(self, corner_radius=0)

        self._build_unlock_screen()
        self._build_dashboard_screen()
        self._show_unlock_screen()

        self.after(150, self._process_ui_events)
        self.after(1000, self._check_inactivity_timer)

    # =========================================================================
    # ENCRYPTED VAULT INDEX MANAGEMENT (IN-MEMORY DECRYPTION)
    # =========================================================================
    def _load_or_init_vault_index(self, password: str) -> dict[str, dict]:
        """Decrypts vault_index.fsafe directly into RAM without creating a temp file."""
        index_data: dict[str, dict] = {}

        if INDEX_FILE.is_file():
            buf = decrypt_to_memory(INDEX_FILE, password)
            try:
                index_data = json.loads(buf.decode("utf-8"))
            finally:
                for i in range(len(buf)):
                    buf[i] = 0
                buf.clear()
        else:
            self._save_vault_index(password, index_data)

        existing_files = {
            p.name for p in VAULT_DIR.glob(f"*{ENCRYPTED_EXT}") if p.name != INDEX_FILE.name
        }
        for k in list(index_data.keys()):
            if k not in existing_files:
                del index_data[k]

        for fname in existing_files:
            if fname not in index_data:
                fpath = VAULT_DIR / fname
                orig_size = max(0, fpath.stat().st_size - HEADER_SIZE)
                index_data[fname] = {
                    "original_name": fname.removesuffix(ENCRYPTED_EXT),
                    "original_dir": str(VAULT_DIR),
                    "size": orig_size,
                }

        return index_data

    def _save_vault_index(self, password: str, index_data: dict[str, dict]) -> None:
        temp_json = VAULT_DIR / f".idx_{uuid.uuid4().hex}.tmp"
        try:
            temp_json.write_text(json.dumps(index_data, indent=2), encoding="utf-8")
            encrypt_file(temp_json, INDEX_FILE, password)
        finally:
            if temp_json.exists():
                shred_file(temp_json, is_ssd=True)

    # =========================================================================
    # 1. UNLOCK SCREEN
    # =========================================================================
    def _build_unlock_screen(self):
        card = ctk.CTkFrame(self.unlock_frame, width=440, height=360, corner_radius=12)
        card.place(relx=0.5, rely=0.5, anchor="center")

        title = ctk.CTkLabel(
            card, text="🔒 File Safe Vault", font=ctk.CTkFont(size=24, weight="bold")
        )
        title.pack(pady=(28, 6), padx=30)

        subtitle = ctk.CTkLabel(
            card,
            text=f"Vault Storage: {VAULT_DIR}\nEnter your Master Password to authenticate and view stored files.",
            font=ctk.CTkFont(size=12),
            text_color="gray70",
        )
        subtitle.pack(pady=(0, 20), padx=30)

        pw_row = ctk.CTkFrame(card, fg_color="transparent")
        pw_row.pack(fill="x", padx=30)

        self.pw_entry = ctk.CTkEntry(
            pw_row,
            placeholder_text="Master Password...",
            show="•",
            height=40,
            font=ctk.CTkFont(size=14),
        )
        self.pw_entry.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.pw_entry.bind("<KeyRelease>", self._on_password_typed)
        self.pw_entry.bind("<Return>", lambda _: self._unlock_vault())

        self._pw_visible = False
        self.eye_btn = ctk.CTkButton(
            pw_row,
            text="👁",
            width=42,
            height=40,
            fg_color="gray25",
            hover_color="gray35",
            command=self._toggle_password_visibility,
        )
        self.eye_btn.pack(side="right")

        self.strength_bar = ctk.CTkProgressBar(card, height=8)
        self.strength_bar.pack(fill="x", padx=30, pady=(14, 4))
        self.strength_bar.set(0)

        self.strength_label = ctk.CTkLabel(
            card, text="Password Strength: Empty", font=ctk.CTkFont(size=12), anchor="w"
        )
        self.strength_label.pack(fill="x", padx=30, pady=(0, 18))

        self.unlock_btn = ctk.CTkButton(
            card,
            text="Unlock Vault",
            height=42,
            font=ctk.CTkFont(size=15, weight="bold"),
            command=self._unlock_vault,
        )
        self.unlock_btn.pack(fill="x", padx=30, pady=(0, 28))

    def _toggle_password_visibility(self):
        self._pw_visible = not self._pw_visible
        self.pw_entry.configure(show="" if self._pw_visible else "•")
        self.eye_btn.configure(text="🙈" if self._pw_visible else "👁")

    def _on_password_typed(self, _event=None):
        pw = self.pw_entry.get()
        score, label, color = calculate_password_strength(pw)
        self.strength_bar.set(score)
        self.strength_bar.configure(progress_color=color)
        self.strength_label.configure(text=f"Password Strength: {label}", text_color=color)

    def _unlock_vault(self):
        pw = self.pw_entry.get()
        if not pw:
            messagebox.showwarning("Validation Error", "Master password cannot be empty.")
            return

        self.unlock_btn.configure(state="disabled", text="Verifying Vault...")
        self.update_idletasks()

        try:
            loaded_index = self._load_or_init_vault_index(pw)
        except DecryptionError:
            self.unlock_btn.configure(state="normal", text="Unlock Vault")
            messagebox.showerror(
                "Authentication Failed",
                "Invalid Master Password for this Vault.",
            )
            return
        except Exception as exc:
            self.unlock_btn.configure(state="normal", text="Unlock Vault")
            messagebox.showerror("Vault Error", f"Could not open vault index:\n{exc}")
            return

        self.unlock_btn.configure(state="normal", text="Unlock Vault")
        self._session_secret = bytearray(pw.encode("utf-8"))
        del pw

        self.pw_entry.delete(0, "end")
        self._on_password_typed()

        self.vault_index = loaded_index
        self._is_unlocked = True
        self._last_activity_ts = time.monotonic()

        self.unlock_frame.pack_forget()
        self.dashboard_frame.pack(fill="both", expand=True)
        self._refresh_table_view()

    # =========================================================================
    # 2. VAULT DASHBOARD
    # =========================================================================
    def _build_dashboard_screen(self):
        top_bar = ctk.CTkFrame(self.dashboard_frame, height=50, corner_radius=0)
        top_bar.pack(fill="x")

        title_lbl = ctk.CTkLabel(
            top_bar, text="🛡️ File Safe Vault Contents", font=ctk.CTkFont(size=18, weight="bold")
        )
        title_lbl.pack(side="left", padx=20, pady=12)

        self.lock_btn = ctk.CTkButton(
            top_bar,
            text="Lock Now",
            width=100,
            height=32,
            fg_color="#c0392b",
            hover_color="#922b21",
            command=self._lock_vault,
        )
        self.lock_btn.pack(side="right", padx=20, pady=10)

        self.timer_label = ctk.CTkLabel(
            top_bar, text="Auto-Lock: 05:00", font=ctk.CTkFont(size=13), text_color="gray75"
        )
        self.timer_label.pack(side="right", padx=10)

        dnd_text = (
            "📥 Drag & Drop files here or click '+ Add Files' to move them into your encrypted Vault"
            if HAS_DND
            else "📥 Click '+ Add Files' to queue files to be encrypted and moved into your Vault"
        )
        self.drop_zone = ctk.CTkFrame(
            self.dashboard_frame, height=95, corner_radius=10, border_width=2, border_color="gray40"
        )
        self.drop_zone.pack(fill="x", padx=20, pady=(14, 8))

        drop_lbl = ctk.CTkLabel(
            self.drop_zone, text=dnd_text, font=ctk.CTkFont(size=13), text_color="gray80"
        )
        drop_lbl.pack(pady=(14, 8))

        btn_row = ctk.CTkFrame(self.drop_zone, fg_color="transparent")
        btn_row.pack(pady=(0, 12))

        add_btn = ctk.CTkButton(btn_row, text="+ Add Files to Queue", width=160, command=self._browse_files)
        add_btn.pack(side="left", padx=6)

        if HAS_DND:
            self.drop_zone.drop_target_register(DND_FILES)
            self.drop_zone.dnd_bind("<<Drop>>", self._on_drop_files)

        # Options Row
        opts_frame = ctk.CTkFrame(self.dashboard_frame, fg_color="transparent")
        opts_frame.pack(fill="x", padx=20, pady=(2, 6))

        self.shred_var = ctk.BooleanVar(value=True)
        shred_cb = ctk.CTkCheckBox(
            opts_frame,
            text="Shred original file after moving to Vault (CSPRNG + fsync + unlink)",
            variable=self.shred_var,
        )
        shred_cb.pack(side="left", padx=(0, 20))

        self.ssd_var = ctk.BooleanVar(value=True)
        ssd_cb = ctk.CTkCheckBox(
            opts_frame,
            text="Target storage is SSD / NVMe (Show Wear-Leveling Advisory)",
            variable=self.ssd_var,
        )
        ssd_cb.pack(side="left")

        # Table Header
        header_frame = ctk.CTkFrame(self.dashboard_frame, height=34, corner_radius=6, fg_color="gray20")
        header_frame.pack(fill="x", padx=20, pady=(6, 2))
        header_frame.grid_columnconfigure(0, weight=4)
        header_frame.grid_columnconfigure(1, weight=1)
        header_frame.grid_columnconfigure(2, weight=2)
        header_frame.grid_columnconfigure(3, weight=3)

        ctk.CTkLabel(header_frame, text="File Name", font=ctk.CTkFont(weight="bold"), anchor="w").grid(
            row=0, column=0, sticky="ew", padx=12, pady=6
        )
        ctk.CTkLabel(header_frame, text="Original Size", font=ctk.CTkFont(weight="bold"), anchor="w").grid(
            row=0, column=1, sticky="ew", padx=8, pady=6
        )
        ctk.CTkLabel(header_frame, text="Vault Status", font=ctk.CTkFont(weight="bold"), anchor="w").grid(
            row=0, column=2, sticky="ew", padx=8, pady=6
        )
        ctk.CTkLabel(header_frame, text="Actions", font=ctk.CTkFont(weight="bold"), anchor="center").grid(
            row=0, column=3, sticky="ew", padx=8, pady=6
        )

        self.queue_scroll = ctk.CTkScrollableFrame(self.dashboard_frame, corner_radius=6)
        self.queue_scroll.pack(fill="both", expand=True, padx=20, pady=(0, 10))

        # Bottom Controls
        bottom_frame = ctk.CTkFrame(self.dashboard_frame, fg_color="transparent")
        bottom_frame.pack(fill="x", padx=20, pady=(0, 16))

        self.progress_bar = ctk.CTkProgressBar(bottom_frame, height=12)
        self.progress_bar.pack(fill="x", pady=(0, 8))
        self.progress_bar.set(0)

        self.status_label = ctk.CTkLabel(
            bottom_frame, text="Vault unlocked.", font=ctk.CTkFont(size=12), text_color="gray70", anchor="w"
        )
        self.status_label.pack(side="left")

        self.decrypt_all_btn = ctk.CTkButton(
            bottom_frame,
            text="🔓 Decrypt All to Folder...",
            width=180,
            fg_color="#2980b9",
            hover_color="#1f618d",
            command=self._decrypt_all_vault_files,
        )
        self.decrypt_all_btn.pack(side="right", padx=(8, 0))

        self.encrypt_all_btn = ctk.CTkButton(
            bottom_frame,
            text="🔐 Encrypt Queued into Vault",
            width=200,
            fg_color="#27ae60",
            hover_color="#1e8449",
            command=self._encrypt_pending_files,
        )
        self.encrypt_all_btn.pack(side="right")

    # =========================================================================
    # 3. TABLE RENDERING & IN-MEMORY VIEWER ACTION
    # =========================================================================
    def _refresh_table_view(self):
        for row_info in self.table_rows.values():
            row_info["frame"].destroy()
        self.table_rows.clear()

        for vault_fname, meta in self.vault_index.items():
            self._create_table_row(
                row_id=f"vault:{vault_fname}",
                display_name=meta["original_name"],
                size_bytes=meta["size"],
                status_text="In Vault (Encrypted)",
                status_color="#2ecc71",
                is_in_vault=True,
                vault_fname=vault_fname,
            )

        for filepath in self.pending_files:
            if filepath.is_file():
                self._create_table_row(
                    row_id=f"pending:{filepath}",
                    display_name=filepath.name,
                    size_bytes=filepath.stat().st_size,
                    status_text="Queued for Encryption",
                    status_color="#f39c12",
                    is_in_vault=False,
                    source_path=filepath,
                )

    def _create_table_row(
        self,
        row_id: str,
        display_name: str,
        size_bytes: int,
        status_text: str,
        status_color: str,
        is_in_vault: bool,
        vault_fname: str | None = None,
        source_path: Path | None = None,
    ):
        row_frame = ctk.CTkFrame(self.queue_scroll, corner_radius=4, fg_color="gray17")
        row_frame.pack(fill="x", pady=3)
        row_frame.grid_columnconfigure(0, weight=4)
        row_frame.grid_columnconfigure(1, weight=1)
        row_frame.grid_columnconfigure(2, weight=2)
        row_frame.grid_columnconfigure(3, weight=3)

        ctk.CTkLabel(row_frame, text=display_name, anchor="w").grid(
            row=0, column=0, sticky="ew", padx=10, pady=6
        )
        ctk.CTkLabel(row_frame, text=format_size(size_bytes), anchor="w", text_color="gray75").grid(
            row=0, column=1, sticky="ew", padx=8, pady=6
        )
        status_lbl = ctk.CTkLabel(row_frame, text=status_text, anchor="w", text_color=status_color)
        status_lbl.grid(row=0, column=2, sticky="ew", padx=8, pady=6)

        action_frame = ctk.CTkFrame(row_frame, fg_color="transparent")
        action_frame.grid(row=0, column=3, padx=8, pady=4)

        if is_in_vault and vault_fname:
            view_btn = ctk.CTkButton(
                action_frame,
                text="👁 View in RAM",
                width=110,
                height=26,
                fg_color="#8e44ad",
                hover_color="#6c3483",
                command=lambda vf=vault_fname: self._preview_vault_file_in_memory(vf),
            )
            view_btn.pack(side="left", padx=4)

            dec_btn = ctk.CTkButton(
                action_frame,
                text="Restore / Export",
                width=115,
                height=26,
                fg_color="#2980b9",
                hover_color="#1f618d",
                command=lambda vf=vault_fname: self._decrypt_single_vault_file(vf),
            )
            dec_btn.pack(side="left", padx=4)
        elif source_path:
            rem_btn = ctk.CTkButton(
                action_frame,
                text="Remove",
                width=80,
                height=26,
                fg_color="gray30",
                hover_color="#c0392b",
                command=lambda p=source_path: self._remove_pending(p),
            )
            rem_btn.pack(side="left", padx=4)

        self.table_rows[row_id] = {
            "frame": row_frame,
            "status_lbl": status_lbl,
        }

    def _preview_vault_file_in_memory(self, vault_fname: str):
        """Decrypts a vault file into a bytearray on a worker thread and opens the RAM viewer."""
        if self._worker_busy or not self._session_secret or vault_fname not in self.vault_index:
            return

        meta = self.vault_index[vault_fname]
        orig_name = meta["original_name"]
        enc_path = VAULT_DIR / vault_fname

        self._set_worker_busy(True)
        self.status_label.configure(text=f"Decrypting '{orig_name}' into RAM...")
        secret_copy = bytearray(self._session_secret)

        threading.Thread(
            target=self._preview_worker,
            args=(enc_path, orig_name, secret_copy),
            daemon=True,
        ).start()

    def _preview_worker(self, enc_path: Path, orig_name: str, secret_buf: bytearray):
        try:
            password_str = secret_buf.decode("utf-8")
            raw_buffer = decrypt_to_memory(enc_path, password_str)
            self.ui_event_queue.put(("open_preview", orig_name, raw_buffer))
        except (DecryptionError, ValueError, OSError) as exc:
            self.ui_event_queue.put(("error_dialog", f"Cannot preview '{orig_name}':\n{exc}"))
            self.ui_event_queue.put(("done", "Preview aborted."))
        finally:
            for i in range(len(secret_buf)):
                secret_buf[i] = 0
            del password_str

    def _browse_files(self):
        paths = filedialog.askopenfilenames(title="Select Files to Move into Vault")
        for p in paths:
            self._queue_plaintext_file(Path(p))
        self._refresh_table_view()

    def _on_drop_files(self, event):
        for f in self.tk.splitlist(event.data):
            self._queue_plaintext_file(Path(f))
        self._refresh_table_view()

    def _queue_plaintext_file(self, filepath: Path):
        if not filepath.is_file():
            return
        if filepath.resolve().parent == VAULT_DIR.resolve():
            return
        if filepath not in self.pending_files:
            self.pending_files.append(filepath)

    def _remove_pending(self, filepath: Path):
        if self._worker_busy:
            return
        if filepath in self.pending_files:
            self.pending_files.remove(filepath)
            self._refresh_table_view()

    # =========================================================================
    # 4. BACKGROUND CRYPTO WORKERS (ENCRYPT / DECRYPT)
    # =========================================================================
    def _encrypt_pending_files(self):
        if self._worker_busy or not self._session_secret:
            return
        if not self.pending_files:
            messagebox.showinfo("Queue Empty", "Add files first to encrypt them into the Vault.")
            return

        self._set_worker_busy(True)
        targets = list(self.pending_files)
        secret_copy = bytearray(self._session_secret)
        shred_enabled = self.shred_var.get()
        is_ssd = self.ssd_var.get()

        threading.Thread(
            target=self._encrypt_worker,
            args=(targets, secret_copy, shred_enabled, is_ssd),
            daemon=True,
        ).start()

    def _encrypt_worker(
        self,
        targets: list[Path],
        secret_buf: bytearray,
        shred_enabled: bool,
        is_ssd: bool,
    ):
        total = len(targets)
        ssd_notice_shown = False

        try:
            password_str = secret_buf.decode("utf-8")

            for idx, filepath in enumerate(targets, start=1):
                row_id = f"pending:{filepath}"
                self.ui_event_queue.put(("row_status", row_id, "Encrypting to Vault...", "#3498db"))
                self.ui_event_queue.put(("global_status", f"Encrypting {filepath.name} ({idx}/{total})..."))

                try:
                    orig_size = filepath.stat().st_size
                    vault_fname = f"{uuid.uuid4().hex}{ENCRYPTED_EXT}"
                    vault_dest = VAULT_DIR / vault_fname

                    encrypt_file(filepath, vault_dest, password_str)

                    if shred_enabled:
                        shred_file(filepath, is_ssd=is_ssd)
                        if is_ssd:
                            ssd_notice_shown = True
                    else:
                        filepath.unlink()

                    self.vault_index[vault_fname] = {
                        "original_name": filepath.name,
                        "original_dir": str(filepath.parent),
                        "size": orig_size,
                    }
                    self._save_vault_index(password_str, self.vault_index)
                    self.pending_files.remove(filepath)

                except (FileLockedError, ShredderError, OSError) as exc:
                    self.ui_event_queue.put(("row_status", row_id, f"Failed: {type(exc).__name__}", "#e74c3c"))
                    self.ui_event_queue.put(("error_dialog", f"Error processing '{filepath.name}':\n{exc}"))

                self.ui_event_queue.put(("progress", idx / total))

            if ssd_notice_shown:
                self.ui_event_queue.put(("info_dialog", "SSD Advisory", SSD_WEAR_LEVELING_WARNING))

            self.ui_event_queue.put(("done", f"Moved {total} file(s) into Vault."))

        finally:
            for i in range(len(secret_buf)):
                secret_buf[i] = 0
            del password_str

    def _decrypt_single_vault_file(self, vault_fname: str):
        if self._worker_busy or not self._session_secret or vault_fname not in self.vault_index:
            return

        meta = self.vault_index[vault_fname]
        initial_dir = meta.get("original_dir", str(Path.home()))
        if not Path(initial_dir).is_dir():
            initial_dir = str(Path.home())

        dest_path_str = filedialog.asksaveasfilename(
            title="Restore & Decrypt File As",
            initialdir=initial_dir,
            initialfile=meta["original_name"],
        )
        if not dest_path_str:
            return

        self._set_worker_busy(True)
        secret_copy = bytearray(self._session_secret)
        threading.Thread(
            target=self._decrypt_worker,
            args=([(vault_fname, Path(dest_path_str))], secret_copy),
            daemon=True,
        ).start()

    def _decrypt_all_vault_files(self):
        if self._worker_busy or not self._session_secret:
            return
        if not self.vault_index:
            messagebox.showinfo("Vault Empty", "There are no encrypted files in the Vault.")
            return

        target_dir_str = filedialog.askdirectory(title="Select Destination Folder to Restore Vault Files")
        if not target_dir_str:
            return

        target_dir = Path(target_dir_str)
        jobs = [
            (vf, target_dir / meta["original_name"])
            for vf, meta in self.vault_index.items()
        ]

        self._set_worker_busy(True)
        secret_copy = bytearray(self._session_secret)
        threading.Thread(
            target=self._decrypt_worker,
            args=(jobs, secret_copy),
            daemon=True,
        ).start()

    def _decrypt_worker(self, jobs: list[tuple[str, Path]], secret_buf: bytearray):
        total = len(jobs)
        try:
            password_str = secret_buf.decode("utf-8")

            for idx, (vault_fname, out_path) in enumerate(jobs, start=1):
                row_id = f"vault:{vault_fname}"
                self.ui_event_queue.put(("row_status", row_id, "Decrypting...", "#3498db"))
                self.ui_event_queue.put(("global_status", f"Restoring {out_path.name} ({idx}/{total})..."))

                try:
                    enc_path = VAULT_DIR / vault_fname
                    decrypt_file(enc_path, out_path, password_str)

                    enc_path.unlink(missing_ok=True)
                    del self.vault_index[vault_fname]
                    self._save_vault_index(password_str, self.vault_index)

                except (DecryptionError, OSError) as exc:
                    self.ui_event_queue.put(("row_status", row_id, f"Failed: {type(exc).__name__}", "#e74c3c"))
                    self.ui_event_queue.put(("error_dialog", f"Could not restore '{out_path.name}':\n{exc}"))

                self.ui_event_queue.put(("progress", idx / total))

            self.ui_event_queue.put(("done", f"Restored {total} file(s) from Vault."))

        finally:
            for i in range(len(secret_buf)):
                secret_buf[i] = 0
            del password_str

    def _set_worker_busy(self, busy: bool):
        self._worker_busy = busy
        state = "disabled" if busy else "normal"
        self.encrypt_all_btn.configure(state=state)
        self.decrypt_all_btn.configure(state=state)
        if busy:
            self.progress_bar.set(0)

    def _process_ui_events(self):
        while not self.ui_event_queue.empty():
            event = self.ui_event_queue.get_nowait()
            kind = event[0]

            if kind == "row_status":
                _, row_id, text, color = event
                if row_id in self.table_rows:
                    self.table_rows[row_id]["status_lbl"].configure(text=text, text_color=color)

            elif kind == "global_status":
                self.status_label.configure(text=event[1])

            elif kind == "progress":
                self.progress_bar.set(event[1])

            elif kind == "open_preview":
                _, orig_name, raw_buffer = event
                self._set_worker_busy(False)
                self.progress_bar.set(1.0)
                self.status_label.configure(text=f"Viewing '{orig_name}' in RAM.")
                modal = InMemoryPreviewModal(self, orig_name, raw_buffer)
                self.active_previews.append(modal)

            elif kind == "error_dialog":
                messagebox.showerror("Operation Error", event[1])

            elif kind == "info_dialog":
                messagebox.showinfo(event[1], event[2])

            elif kind == "done":
                self.status_label.configure(text=event[1])
                self._set_worker_busy(False)
                self._refresh_table_view()

        self.after(150, self._process_ui_events)

    # =========================================================================
    # 5. AUTO-LOCK WATCHDOG & MEMORY SCRUBBING
    # =========================================================================
    def _record_user_activity(self, _event=None):
        if self._is_unlocked:
            self._last_activity_ts = time.monotonic()

    def _check_inactivity_timer(self):
        if self._is_unlocked:
            if self._worker_busy:
                self._last_activity_ts = time.monotonic()

            elapsed = time.monotonic() - self._last_activity_ts
            remaining = max(0, int(INACTIVITY_TIMEOUT_SECONDS - elapsed))
            mins, secs = divmod(remaining, 60)
            self.timer_label.configure(text=f"Auto-Lock: {mins:02d}:{secs:02d}")

            if remaining == 0:
                self._lock_vault(auto_triggered=True)

        self.after(1000, self._check_inactivity_timer)

    def _scrub_session_secret(self):
        if self._session_secret is not None:
            for i in range(len(self._session_secret)):
                self._session_secret[i] = 0
            self._session_secret = None

    def _lock_vault(self, auto_triggered: bool = False):
        if self._worker_busy:
            return

        # Close all open RAM preview windows and wipe their buffers
        for modal in list(self.active_previews):
            modal.close_and_scrub()
        self.active_previews.clear()

        self._scrub_session_secret()
        self.vault_index.clear()
        self.pending_files.clear()
        self._refresh_table_view()
        self._is_unlocked = False
        self._show_unlock_screen()
        if auto_triggered:
            messagebox.showinfo(
                "Vault Auto-Locked",
                "Session locked automatically after 5 minutes of inactivity. "
                "All open RAM previews and key material have been wiped.",
            )

    def _show_unlock_screen(self):
        self.dashboard_frame.pack_forget()
        self.unlock_frame.pack(fill="both", expand=True)
        self.pw_entry.focus_set()


if __name__ == "__main__":
    app = FileSafeApp()
    app.mainloop()