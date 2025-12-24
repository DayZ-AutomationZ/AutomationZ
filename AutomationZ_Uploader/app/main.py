#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import pathlib
import datetime
import traceback
from dataclasses import dataclass
from typing import List, Optional, Tuple

import ftplib

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

APP_NAME = "AutomationZ Uploader"
APP_VERSION = "1.0.3"

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"
BACKUPS_DIR = BASE_DIR / "backups"
PRESETS_DIR = BASE_DIR / "presets"

PROFILES_PATH = CONFIG_DIR / "profiles.json"
MAPPINGS_PATH = CONFIG_DIR / "mappings.json"
SETTINGS_PATH = CONFIG_DIR / "settings.json"



# ---- theme colors (shared across AutomationZ tools) ----
C_BG = "#333333"       # base background
C_PANEL = "#363636"    # panels
C_TEXT = "#e6e6e6"     # readable light text
C_MUTED = "#b8b8b8"
C_ACCENT = "#4CAF50"   # AutomationZ green
C_WARN = "#ffb74d"
C_BAD = "#ef5350"

def apply_dark_theme(root: tk.Tk) -> ttk.Style:
    """
    Apply the AutomationZ dark theme (clam-based) to a Tk root window.
    Returns the ttk.Style used.
    """
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    root.configure(bg=C_BG)

    # Generic ttk styling
    style.configure(".", background=C_BG, foreground=C_TEXT)
    style.configure("TFrame", background=C_BG)
    style.configure("TLabel", background=C_BG, foreground=C_TEXT)
    style.configure("TLabelFrame", background=C_BG, foreground=C_TEXT)
    style.configure("TLabelFrame.Label", background=C_BG, foreground=C_TEXT)

    # Entries / Combobox
    style.configure("TEntry", fieldbackground=C_PANEL, background=C_PANEL, foreground=C_TEXT, insertcolor=C_TEXT)
    style.configure("TCombobox", fieldbackground=C_PANEL, background=C_PANEL, foreground=C_TEXT, arrowcolor=C_TEXT)
    style.map("TCombobox",
              fieldbackground=[("readonly", C_PANEL)],
              background=[("readonly", C_PANEL)],
              foreground=[("readonly", C_TEXT)])

    # Notebook (tabs)
    style.configure("TNotebook", background=C_BG, borderwidth=0)
    style.configure("TNotebook.Tab", background=C_PANEL, foreground=C_TEXT, padding=(10, 6))
    style.map("TNotebook.Tab",
              background=[("selected", "#242424"), ("active", "#2d2d2d")],
              foreground=[("disabled", C_MUTED)])

    # Buttons (neutral)
    style.configure("TButton", background=C_PANEL, foreground=C_TEXT, borderwidth=1, focusthickness=2, focuscolor=C_ACCENT)
    style.map("TButton",
              background=[("active", "#3a3a3a"), ("pressed", "#3f3f3f")],
              foreground=[("disabled", C_MUTED)])

    # Primary green buttons
    style.configure(
        "Colored.TButton",
        foreground="white",
        background=C_ACCENT,
        bordercolor=C_ACCENT,
        padding=(10, 6),
        font=("Segoe UI", 10, "bold"),
    )
    style.map(
        "Colored.TButton",
        background=[
            ("active", "#66BB6A"),
            ("pressed", "#388E3C"),
            ("disabled", "#555555"),
        ],
        foreground=[
            ("disabled", "#aaaaaa"),
        ],
    )

    # Separators
    style.configure("TSeparator", background="#1f1f1f")

    return style

def style_text_widget(txt: tk.Text) -> None:
    txt.configure(
        bg=C_PANEL,
        fg=C_TEXT,
        insertbackground=C_TEXT,
        selectbackground="#1f3b2b",
        selectforeground="#ffffff",
        relief="flat",
        highlightthickness=1,
        highlightbackground="#1f1f1f",
        highlightcolor=C_ACCENT,
        bd=0
    )

def style_listbox(lb: tk.Listbox) -> None:
    lb.configure(
        bg=C_PANEL,
        fg=C_TEXT,
        selectbackground="#1f3b2b",
        selectforeground="#ffffff",
        relief="flat",
        highlightthickness=1,
        highlightbackground="#1f1f1f",
        highlightcolor=C_ACCENT,
        bd=0
    )

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def norm_remote(path: str) -> str:
    return path.replace("\\", "/").lstrip("/")

def load_json(path: pathlib.Path, default_obj):
    if not path.exists():
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", encoding="utf-8") as f:
            json.dump(default_obj, f, indent=4)
        return default_obj
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

def save_json(path: pathlib.Path, obj) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=4)

class Logger:
    def __init__(self, widget: tk.Text):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.widget = widget
        self.file = LOGS_DIR / ("uploader_" + now_stamp() + ".log")
        self._write(APP_NAME + " v" + APP_VERSION + "\n\n")

    def _write(self, s: str) -> None:
        with open(self.file, "a", encoding="utf-8") as f:
            f.write(s)

    def log(self, level: str, msg: str) -> None:
        line = f"[{level}] {msg}\n"
        self._write(line)
        self.widget.configure(state="normal")
        self.widget.insert("end", line)
        self.widget.see("end")
        self.widget.configure(state="disabled")

    def info(self, msg: str) -> None: self.log("INFO", msg)
    def warn(self, msg: str) -> None: self.log("WARN", msg)
    def error(self, msg: str) -> None: self.log("ERROR", msg)

@dataclass
class Profile:
    name: str
    host: str
    port: int
    username: str
    password: str
    tls: bool
    root: str

@dataclass
class Mapping:
    name: str
    enabled: bool
    local_relpath: str
    remote_path: str
    backup_before_overwrite: bool

def load_profiles() -> Tuple[List[Profile], Optional[str]]:
    obj = load_json(PROFILES_PATH, {"profiles": [], "active_profile": None})
    profiles: List[Profile] = []
    for p in obj.get("profiles", []):
        profiles.append(Profile(
            name=p.get("name","Unnamed"),
            host=p.get("host",""),
            port=int(p.get("port",21)),
            username=p.get("username",""),
            password=p.get("password",""),
            tls=bool(p.get("tls", False)),
            root=p.get("root","/"),
        ))
    return profiles, obj.get("active_profile")

def save_profiles(profiles: List[Profile], active: Optional[str]) -> None:
    save_json(PROFILES_PATH, {"profiles":[p.__dict__ for p in profiles], "active_profile": active})

def load_mappings() -> List[Mapping]:
    obj = load_json(MAPPINGS_PATH, {"mappings": []})
    out: List[Mapping] = []
    for m in obj.get("mappings", []):
        out.append(Mapping(
            name=m.get("name","Unnamed Mapping"),
            enabled=bool(m.get("enabled", True)),
            local_relpath=m.get("local_relpath",""),
            remote_path=m.get("remote_path",""),
            backup_before_overwrite=bool(m.get("backup_before_overwrite", True)),
        ))
    return out

def save_mappings(mappings: List[Mapping]) -> None:
    save_json(MAPPINGS_PATH, {"mappings":[m.__dict__ for m in mappings]})

def load_settings() -> dict:
    return load_json(SETTINGS_PATH, {"app":{"timeout_seconds":20}})

class FTPClient:
    def __init__(self, profile: Profile, timeout: int):
        self.p = profile
        self.timeout = timeout
        self.ftp = None

    def connect(self):
        ftp = ftplib.FTP_TLS(timeout=self.timeout) if self.p.tls else ftplib.FTP(timeout=self.timeout)
        ftp.connect(self.p.host, self.p.port)
        ftp.login(self.p.username, self.p.password)
        if self.p.tls and isinstance(ftp, ftplib.FTP_TLS):
            ftp.prot_p()
        self.ftp = ftp

    def close(self):
        try:
            if self.ftp:
                self.ftp.quit()
        except Exception:
            try:
                if self.ftp:
                    self.ftp.close()
            except Exception:
                pass
        self.ftp = None

    def download(self, remote_full: str, local_path: pathlib.Path) -> bool:
        try:
            local_path.parent.mkdir(parents=True, exist_ok=True)
            with open(local_path, "wb") as f:
                self.ftp.retrbinary("RETR " + remote_full, f.write)
            return True
        except Exception:
            return False

    def upload(self, local_path: pathlib.Path, remote_full: str):
        with open(local_path, "rb") as f:
            self.ftp.storbinary("STOR " + remote_full, f)

    def pwd(self) -> str:
        return self.ftp.pwd()

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.style = apply_dark_theme(self)
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("980x640")
        self.minsize(920, 600)

        self.settings = load_settings()
        self.timeout = int(self.settings.get("app",{}).get("timeout_seconds", 20))

        self.profiles, self.active_profile = load_profiles()
        self.mappings = load_mappings()

        # Remember last selected indices (Tkinter Listbox selection can drop when Entry fields get focus)
        self._last_profile_index: Optional[int] = None
        self._last_mapping_index: Optional[int] = None

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_upload = ttk.Frame(nb)
        self.tab_profiles = ttk.Frame(nb)
        self.tab_mappings = ttk.Frame(nb)
        self.tab_help = ttk.Frame(nb)

        nb.add(self.tab_upload, text="Upload")
        nb.add(self.tab_profiles, text="Profiles")
        nb.add(self.tab_mappings, text="Mappings")
        nb.add(self.tab_help, text="Help")

        log_box = ttk.LabelFrame(self, text="Log")
        log_box.pack(fill="both", expand=False, padx=10, pady=8)
        self.log_text = tk.Text(log_box, height=10, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        style_text_widget(self.log_text)
        self.log = Logger(self.log_text)

        self._build_upload()
        self._build_profiles()
        self._build_mappings()
        self._build_help()

        self.refresh_presets()
        self.refresh_profiles_combo()
        self.refresh_profiles_list()
        self.refresh_mappings_list()
        self.refresh_preview()

    # Upload
    def _build_upload(self):
        f = self.tab_upload
        top = ttk.Frame(f); top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Profile:").grid(row=0, column=0, sticky="w")
        self.cmb_profile = ttk.Combobox(top, state="readonly", width=28)
        self.cmb_profile.grid(row=0, column=1, sticky="w", padx=(6,18))

        ttk.Button(top, text="Test Connection", command=self.test_conn, style="Colored.TButton").grid(row=0, column=2, sticky="w", padx=(0,10))
        ttk.Button(top, text="Open Presets Folder", command=self.open_presets, style="Colored.TButton").grid(row=0, column=3, sticky="w")

        ttk.Label(top, text="Preset:").grid(row=1, column=0, sticky="w", pady=(10,0))
        self.cmb_preset = ttk.Combobox(top, state="readonly", width=28)
        self.cmb_preset.grid(row=1, column=1, sticky="w", padx=(6,18), pady=(10,0))

        ttk.Button(top, text="Refresh Presets", command=self.refresh_presets, style="Colored.TButton").grid(row=1, column=2, sticky="w", padx=(0,10), pady=(10,0))
        ttk.Button(top, text="UPLOAD PRESET", command=self.upload_preset, style="Colored.TButton").grid(row=1, column=3, sticky="w", pady=(10,0))

        mid = ttk.LabelFrame(f, text="Enabled mappings (what will be uploaded)")
        mid.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.lst_preview = tk.Listbox(mid, height=14)
        self.lst_preview.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_preview)

        ttk.Button(f, text="Rebuild Preview", command=self.refresh_preview, style="Colored.TButton").pack(anchor="w", padx=12, pady=(0,12))

    def open_presets(self):
        path = str(PRESETS_DIR)
        try:
            if sys.platform.startswith("win"):
                os.startfile(path)  # type: ignore
            elif sys.platform == "darwin":
                os.system(f'open "{path}"')
            else:
                os.system(f'xdg-open "{path}"')
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh_presets(self):
        presets = [p.name for p in sorted(PRESETS_DIR.iterdir()) if p.is_dir()] if PRESETS_DIR.exists() else []
        self.cmb_preset["values"] = presets
        if presets and self.cmb_preset.get() not in presets:
            self.cmb_preset.set(presets[0])

    def refresh_preview(self):
        self.lst_preview.delete(0, "end")
        preset = (self.cmb_preset.get() or "").strip()
        if not preset:
            self.lst_preview.insert("end", "Pick a preset.")
            return
        preset_dir = PRESETS_DIR / preset
        enabled = [m for m in self.mappings if m.enabled]
        if not enabled:
            self.lst_preview.insert("end", "No enabled mappings. Go to Mappings tab.")
            return
        for m in enabled:
            exists = "OK" if (preset_dir / m.local_relpath).exists() else "MISSING"
            self.lst_preview.insert("end", f"{m.name} | local: {m.local_relpath} ({exists}) -> remote: {m.remote_path}")

    def selected_profile(self) -> Optional[Profile]:
        name = (self.cmb_profile.get() or "").strip()
        for p in self.profiles:
            if p.name == name:
                return p
        return None

    def test_conn(self):
        p = self.selected_profile()
        if not p:
            messagebox.showwarning("No profile", "Create/select a profile in Profiles tab.")
            return
        self.log.info(f"Testing connection to {p.host}:{p.port} TLS={p.tls}")
        cli = FTPClient(p, self.timeout)
        try:
            cli.connect()
            self.log.info("Connected. PWD: " + cli.pwd())
            messagebox.showinfo("OK", "Connected. PWD: " + cli.pwd())
        except Exception as e:
            self.log.error("Connection failed: " + str(e))
            messagebox.showerror("Failed", str(e))
        finally:
            cli.close()

    def upload_preset(self):
        p = self.selected_profile()
        if not p:
            messagebox.showwarning("No profile", "Create/select a profile in Profiles tab.")
            return
        preset = (self.cmb_preset.get() or "").strip()
        if not preset:
            messagebox.showwarning("No preset", "Select a preset.")
            return

        enabled = [m for m in self.mappings if m.enabled]
        if not enabled:
            messagebox.showwarning("No mappings", "No enabled mappings.")
            return

        preset_dir = PRESETS_DIR / preset
        missing = [m.local_relpath for m in enabled if not (preset_dir / m.local_relpath).exists()]
        if missing:
            messagebox.showerror("Missing files", "Missing in preset:\n" + "\n".join(missing))
            return

        if not messagebox.askyesno("Confirm", f"Upload preset '{preset}' to profile '{p.name}'?"):
            return

        root = norm_remote(p.root or "/")
        cli = FTPClient(p, self.timeout)

        try:
            cli.connect()

            for m in enabled:
                local_file = preset_dir / m.local_relpath
                remote_full = "/" + (root.rstrip("/") + "/" + norm_remote(m.remote_path)).strip("/")

                if m.backup_before_overwrite:
                    bdir = BACKUPS_DIR / p.name / preset / now_stamp()
                    bpath = bdir / m.local_relpath
                    ok = cli.download(remote_full, bpath)
                    if ok:
                        self.log.info(f"Backup OK: {remote_full} -> {bpath}")
                    else:
                        self.log.warn(f"Backup skipped/failed: {remote_full}")

                cli.upload(local_file, remote_full)
                self.log.info(f"Uploaded: {local_file} -> {remote_full}")

            messagebox.showinfo("Done", "Upload complete.")
        except Exception as e:
            self.log.error("Upload failed: " + str(e))
            self.log.error(traceback.format_exc())
            messagebox.showerror("Failed", str(e))
        finally:
            cli.close()

    # Profiles
    def _build_profiles(self):
        f = self.tab_profiles
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Profiles")
        left.pack(side="left", fill="both", expand=False)

        self.lst_profiles = tk.Listbox(left, width=28, height=18)
        self.lst_profiles.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_profiles)
        self.lst_profiles.bind("<<ListboxSelect>>", lambda e: self.on_profile_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.profile_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.profile_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Set Active", command=self.profile_set_active, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Profile details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.v_name = tk.StringVar(); self.v_host = tk.StringVar(); self.v_port = tk.StringVar(value="21")
        self.v_user = tk.StringVar(); self.v_pass = tk.StringVar(); self.v_tls = tk.BooleanVar(value=False)
        self.v_root = tk.StringVar(value="/dayzstandalone")

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_name, width=40).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Host").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_host, width=40).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Port").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_port, width=12).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Username").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_user, width=40).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Password").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_pass, width=40, show="*").grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Checkbutton(form, text="Use FTPS (FTP over TLS)", variable=self.v_tls).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Remote root").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_root, width=40).grid(row=r, column=1, sticky="w", pady=2); r+=1

        actions = ttk.Frame(right); actions.pack(fill="x", padx=10, pady=(0,10))
        ttk.Button(actions, text="Save Changes", command=self.profile_save, style="Colored.TButton").pack(side="left")

    def refresh_profiles_combo(self):
        names = [p.name for p in self.profiles]
        self.cmb_profile["values"] = names
        if self.active_profile and self.active_profile in names:
            self.cmb_profile.set(self.active_profile)
        elif names:
            self.cmb_profile.set(names[0])

    def refresh_profiles_list(self):
        self.lst_profiles.delete(0, "end")
        for p in self.profiles:
            suffix = " (active)" if self.active_profile == p.name else ""
            self.lst_profiles.insert("end", p.name + suffix)

    def on_profile_select(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None: return
        self._last_profile_index = idx
        p = self.profiles[idx]
        self.v_name.set(p.name); self.v_host.set(p.host); self.v_port.set(str(p.port))
        self.v_user.set(p.username); self.v_pass.set(p.password); self.v_tls.set(p.tls); self.v_root.set(p.root)

    def profile_new(self):
        n = "Profile_" + str(len(self.profiles) + 1)
        self.profiles.append(Profile(n, "", 21, "", "", False, "/dayzstandalone"))
        self.active_profile = n
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list()
        self.refresh_profiles_combo()

        idx = len(self.profiles) - 1
        self.lst_profiles.selection_clear(0, "end")
        self.lst_profiles.selection_set(idx)
        self.lst_profiles.see(idx)
        self.on_profile_select()

    def profile_delete(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None:
            idx = self._last_profile_index
        if idx is None: return
        p = self.profiles[idx]
        if not messagebox.askyesno("Delete", f"Delete profile '{p.name}'?"): return
        del self.profiles[idx]
        if self.active_profile == p.name:
            self.active_profile = self.profiles[0].name if self.profiles else None
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list(); self.refresh_profiles_combo()

    def profile_set_active(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None:
            idx = self._last_profile_index
        if idx is None: return
        self.active_profile = self.profiles[idx].name
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list(); self.refresh_profiles_combo()

    def profile_save(self):
        # Save Changes works as:
        # - If a profile is selected: update it
        # - If nothing selected: create a new profile from the form fields
        try:
            port = int((self.v_port.get() or "21").strip())
        except ValueError:
            messagebox.showerror("Invalid", "Port must be a number.")
            return

        new_profile = Profile(
            name=self.v_name.get().strip() or "Unnamed",
            host=self.v_host.get().strip(),
            port=port,
            username=self.v_user.get().strip(),
            password=self.v_pass.get(),
            tls=bool(self.v_tls.get()),
            root=self.v_root.get().strip() or "/"
        )

        i = self._sel_index(self.lst_profiles)  # may be None
        if i is None:
            i = self._last_profile_index
        existing_names = [p.name for p in self.profiles]

        if i is None:
            # Create new
            if new_profile.name in existing_names:
                messagebox.showerror("Duplicate name", "A profile with this name already exists. Pick a different name.")
                return
            self.profiles.append(new_profile)
            # Make new profile active for convenience
            self.active_profile = new_profile.name
        else:
            # Update selected
            old_name = self.profiles[i].name
            if new_profile.name != old_name and new_profile.name in existing_names:
                messagebox.showerror("Duplicate name", "A profile with this name already exists. Pick a different name.")
                return
            self.profiles[i] = new_profile
            if self.active_profile == old_name:
                self.active_profile = new_profile.name

        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list()
        self.refresh_profiles_combo()

        # Select the saved profile
        try:
            idx = [p.name for p in self.profiles].index(new_profile.name)
            self.lst_profiles.selection_clear(0, "end")
            self.lst_profiles.selection_set(idx)
            self.lst_profiles.see(idx)
            self.on_profile_select()
        except Exception:
            pass

        messagebox.showinfo("Saved", "Profile saved.")

    # Mappings
    def _build_mappings(self):
        f = self.tab_mappings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Mappings")
        left.pack(side="left", fill="both", expand=False)

        self.lst_mappings = tk.Listbox(left, width=52, height=18)
        self.lst_mappings.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_mappings)
        self.lst_mappings.bind("<<ListboxSelect>>", lambda e: self.on_mapping_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.mapping_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.mapping_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.mapping_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Mapping details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.m_name = tk.StringVar(); self.m_enabled = tk.BooleanVar(value=True)
        self.m_local = tk.StringVar(); self.m_remote = tk.StringVar(); self.m_backup = tk.BooleanVar(value=True)

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.m_name, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Checkbutton(form, text="Enabled", variable=self.m_enabled).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Local file (inside preset folder)").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.m_local, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Remote path (relative to profile root)").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.m_remote, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Checkbutton(form, text="Backup before overwrite", variable=self.m_backup).grid(row=r, column=1, sticky="w", pady=2); r+=1

    def refresh_mappings_list(self):
        self.lst_mappings.delete(0, "end")
        for m in self.mappings:
            flag = "ON" if m.enabled else "OFF"
            self.lst_mappings.insert("end", f"[{flag}] {m.name} | {m.local_relpath} -> {m.remote_path}")

    def on_mapping_select(self):
        idx = self._sel_index(self.lst_mappings)
        if idx is None: return
        self._last_mapping_index = idx
        m = self.mappings[idx]
        self.m_name.set(m.name); self.m_enabled.set(m.enabled)
        self.m_local.set(m.local_relpath); self.m_remote.set(m.remote_path); self.m_backup.set(m.backup_before_overwrite)

    def mapping_new(self):
        self.mappings.append(Mapping(f"Mapping_{len(self.mappings)+1}", True, "", "", True))
        save_mappings(self.mappings)
        self.refresh_mappings_list(); self.refresh_preview()

    def mapping_delete(self):
        idx = self._sel_index(self.lst_mappings)
        if idx is None: return
        m = self.mappings[idx]
        if not messagebox.askyesno("Delete", f"Delete mapping '{m.name}'?"): return
        del self.mappings[idx]
        save_mappings(self.mappings)
        self.refresh_mappings_list(); self.refresh_preview()

    def mapping_save(self):
        idx = self._sel_index(self.lst_mappings)
        if idx is None:
            idx = self._last_mapping_index
        if idx is None:
            messagebox.showwarning("No mapping", "Select a mapping.")
            return
        self.mappings[idx] = Mapping(
            name=self.m_name.get().strip() or "Unnamed",
            enabled=bool(self.m_enabled.get()),
            local_relpath=self.m_local.get().strip(),
            remote_path=self.m_remote.get().strip(),
            backup_before_overwrite=bool(self.m_backup.get()),
        )
        save_mappings(self.mappings)
        self.refresh_mappings_list(); self.refresh_preview()
        messagebox.showinfo("Saved", "Mapping saved.")

    def _build_help(self):
        t = tk.Text(self.tab_help, wrap="word")
        t.pack(fill="both", expand=True, padx=12, pady=12)
        style_text_widget(t)
        t.insert("1.0",
            "AutomationZ Uploader\n\n"
            "Created By Danny van den Brande\n\n"
"This tool uploads preset files to your DayZ server via FTP/FTPS.\n"
"It is NOT a DayZ mod and is NOT added to server parameters.\n\n"

"HOW IT WORKS (IMPORTANT)\n"
"The uploader works with three parts:\n"
"  1) Presets  - Local folders with config files\n"
"  2) Mappings - Rules that say which file goes where\n"
"  3) Profiles - FTP login + server root folder\n\n"

"UPLOAD LOGIC\n"
"The upload always works like this:\n"
"  presets/<SelectedPreset>/<local_relpath>\n"
"    --> <ProfileRoot>/<remote_path>\n\n"

"PRESETS\n"
"A preset is simply a folder inside the presets directory.\n"
"You select ONE preset in the dropdown.\n"
"Only files inside that preset folder can be uploaded.\n\n"

"Example:\n"
"  presets/raid_on/BBP_Raid_on.json\n"
"  presets/raid_off/BBP_Raid_off.json\n\n"

"MAPPINGS\n"
"A mapping defines:\n"
"  - local_relpath : filename inside the preset folder\n"
"  - remote_path  : file path on the server (relative to root)\n\n"

"local_relpath RULES:\n"
"  - Do NOT include 'presets/'\n"
"  - Use only the filename or subfolder inside the preset\n"
"  - Filenames are case-sensitive on Linux servers\n\n"

"GOOD:\n"
"  BBP_Raid_on.json\n"
"  db/messages.xml\n\n"

"BAD:\n"
"  presets/raid_on/BBP_Raid_on.json\n\n"

"remote_path RULES:\n"
"  - Path is relative to the profile root\n"
"  - Use forward slashes (/)\n"
"  - Exact filename match is required to overwrite\n\n"

"IMPORTANT ABOUT OVERWRITING FILES\n"
"FTP overwrites ONLY when the remote filename matches EXACTLY.\n"
"Different name (BBP vs BPP, case, spaces) = new file created.\n\n"

"PROFILES (FTP SETTINGS)\n"
"A profile stores your FTP login and a root folder.\n"
"Typical Nitrado root:\n"
"  /dayzstandalone\n\n"

"Example final path:\n"
"  Root:        /dayzstandalone\n"
"  remote_path: config/BaseBuildingPlus/BBP_Settings.json\n"
"  Result:      /dayzstandalone/config/BaseBuildingPlus/BBP_Settings.json\n\n"

"MISSING FILES IN PREVIEW\n"
"If Preview shows MISSING:\n"
"  - The file does not exist in the selected preset folder\n"
"  - Or the filename does not match exactly\n"
"  - Or another enabled mapping expects a different file\n\n"

"BACKUPS\n"
"If backup is enabled, the original server file is downloaded\n"
"before overwriting.\n"
"Backups are stored in:\n"
"  backups/<profile>/<preset>/<timestamp>/\n\n"

"COMMON DAYZ PATHS\n"
"Vanilla messages.xml:\n"
"  mpmissions/dayzOffline.chernarusplus/db/messages.xml\n\n"

"Expansion notifications (common):\n"
"  config/ExpansionMod/Settings/NotificationSchedulerSettings.json\n"
        )
        t.configure(state="disabled")

    def _sel_index(self, lb: tk.Listbox) -> Optional[int]:
        sel = lb.curselection()
        return int(sel[0]) if sel else None

    def sel_index(self, lb):
        # Backwards-compatible alias
        return self._sel_index(lb)

def main():
    for p in [CONFIG_DIR, LOGS_DIR, BACKUPS_DIR, PRESETS_DIR]:
        p.mkdir(parents=True, exist_ok=True)
    App().mainloop()

if __name__ == "__main__":
    main()
