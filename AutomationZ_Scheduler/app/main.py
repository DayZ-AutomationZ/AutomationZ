#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import pathlib
import datetime
import traceback
from dataclasses import dataclass
from typing import List, Optional

import ftplib

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

APP_NAME = "AutomationZ Scheduler"
APP_VERSION = "1.0.0"

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"
PRESETS_DIR = BASE_DIR / "presets"   # optional, user can point this to same presets folder as Uploader

PROFILES_PATH = CONFIG_DIR / "profiles.json"
MAPPINGS_PATH = CONFIG_DIR / "mappings.json"
TASKS_PATH = CONFIG_DIR / "tasks.json"
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
        self.file = LOGS_DIR / ("scheduler_" + now_stamp() + ".log")
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

def load_profiles() -> List[Profile]:
    obj = load_json(PROFILES_PATH, {"profiles": []})
    out: List[Profile] = []
    for p in obj.get("profiles", []):
        out.append(Profile(
            name=p.get("name","Unnamed"),
            host=p.get("host",""),
            port=int(p.get("port",21)),
            username=p.get("username",""),
            password=p.get("password",""),
            tls=bool(p.get("tls", False)),
            root=p.get("root","/dayzstandalone"),
        ))
    return out

def save_profiles(profiles: List[Profile]) -> None:
    save_json(PROFILES_PATH, {"profiles":[p.__dict__ for p in profiles]})

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

def load_tasks() -> dict:
    return load_json(TASKS_PATH, {"tasks": []})

def save_tasks(obj: dict) -> None:
    save_json(TASKS_PATH, obj)

def load_settings() -> dict:
    return load_json(SETTINGS_PATH, {
        "app": {
            "timeout_seconds": 20,
            "tick_seconds": 20,
            "presets_dir": str(PRESETS_DIR),
            "auto_start": False
        }
    })

def save_settings(obj: dict) -> None:
    save_json(SETTINGS_PATH, obj)

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
        self.geometry("1040x700")
        self.minsize(980, 640)

        self.settings = load_settings()
        self.timeout = int(self.settings.get("app", {}).get("timeout_seconds", 20))
        self.tick_seconds = int(self.settings.get("app", {}).get("tick_seconds", 20))
        self.presets_dir = pathlib.Path(self.settings.get("app", {}).get("presets_dir", str(PRESETS_DIR))).resolve()
        self.auto_start = bool(self.settings.get("app", {}).get("auto_start", False))

        self.profiles: List[Profile] = load_profiles()
        self.mappings: List[Mapping] = load_mappings()
        self.tasks_obj: dict = load_tasks()

        self.scheduler_running = False

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_dashboard = ttk.Frame(nb)
        self.tab_tasks = ttk.Frame(nb)
        self.tab_profiles = ttk.Frame(nb)
        self.tab_mappings = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)

        nb.add(self.tab_dashboard, text="Dashboard")
        nb.add(self.tab_tasks, text="Tasks")
        nb.add(self.tab_profiles, text="Profiles")
        nb.add(self.tab_mappings, text="Mappings")
        nb.add(self.tab_settings, text="Settings")

        log_box = ttk.LabelFrame(self, text="Log")
        log_box.pack(fill="both", expand=False, padx=10, pady=8)
        self.log_text = tk.Text(log_box, height=10, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        style_text_widget(self.log_text)
        self.log = Logger(self.log_text)

        self._build_dashboard()
        self._build_tasks()
        self._build_profiles()
        self._build_mappings()
        self._build_settings()

        self.refresh_tasks_list()
        self.refresh_profiles_list()
        self.refresh_mappings_list()
        self._tick()  # scheduler timer

        if self.auto_start:
            self.start_scheduler()

    # ---------------- Dashboard ----------------
    def _build_dashboard(self):
        f = self.tab_dashboard
        top = ttk.Frame(f); top.pack(fill="x", padx=12, pady=10)

        self.lbl_state = ttk.Label(top, text="Scheduler: STOPPED", font=("TkDefaultFont", 12, "bold"))
        self.lbl_state.pack(side="left")

        ttk.Button(top, text="Start", command=self.start_scheduler, style="Colored.TButton").pack(side="left", padx=10)
        ttk.Button(top, text="Stop", command=self.stop_scheduler, style="Colored.TButton").pack(side="left")
        ttk.Button(top, text="Run Selected Task Now", command=self.task_run_now, style="Colored.TButton").pack(side="left", padx=10)
        ttk.Button(top, text="Test Connection (Selected Profile)", command=self.test_conn_selected_profile, style="Colored.TButton").pack(side="left", padx=10)

        info = ttk.LabelFrame(f, text="How it works")
        info.pack(fill="both", expand=True, padx=12, pady=(0,10))
        msg = (
            "AutomationZ Scheduler\n\n"
    "This application automates scheduled file uploads to remote servers using FTP or FTPS.\n"
    "It is designed to run continuously (24/7) or only during the periods when automation is needed.\n\n"

    "What this tool does:\n"
    "- Executes scheduled tasks based on day and time (no dates required)\n"
    "- Uploads predefined preset files to one or more servers\n"
    "- Safely overwrites remote files using exact path mapping\n"
    "- Supports multiple servers through reusable profiles\n\n"

    "What this tool does NOT do:\n"
    "- It is NOT a DayZ mod\n"
    "- It does NOT modify game logic\n"
    "- It does NOT require server parameter changes\n\n"

    "Why it exists:\n"
    "Server owners often need to switch configurations at specific times\n"
    "(weekend raids, events, maintenance modes, layout changes, etc.)\n"
    "This tool removes the need to manually upload files or be online\n"
    "when those changes need to happen.\n\n"

    "Typical use cases:\n"
    "- Game servers: raid schedules, event configs, loot rotations\n"
    "- Websites: page or layout changes on specific days\n"
    "- Any server where files must change automatically at set times\n\n"
    "DayZ AutomationZ Scheduler is free and open-source software.\n\n"
"If this tool helps you automate server tasks, save time,\n"
"or manage multiple servers more easily,\n"
"consider supporting development with a donation.\n\n"
"Donations are optional, but appreciated and help\n"
"support ongoing development and improvements.\n\n"
"Support link:\n"
"https://ko-fi.com/dannyvandenbrande\n"

    "Created by Danny van den Brande \n"
        )
        t = tk.Text(info, wrap="word", height=12)
        t.pack(fill="both", expand=True, padx=8, pady=8)
        style_text_widget(t)
        t.insert("1.0", msg)
        t.configure(state="disabled")

    def _set_state_label(self):
        if self.scheduler_running:
            self.lbl_state.configure(text=f"Scheduler: RUNNING (tick {self.tick_seconds}s)")
        else:
            self.lbl_state.configure(text="Scheduler: STOPPED")

    def start_scheduler(self):
        self.scheduler_running = True
        self._set_state_label()
        self.log.info("Scheduler started.")

    def stop_scheduler(self):
        self.scheduler_running = False
        self._set_state_label()
        self.log.warn("Scheduler stopped.")

    # ---------------- Tasks ----------------
    def _build_tasks(self):
        f = self.tab_tasks
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Tasks")
        left.pack(side="left", fill="both", expand=False)

        self.lst_tasks = tk.Listbox(left, width=52, height=20, exportselection=False)
        self.lst_tasks.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_tasks)
        self.lst_tasks.bind("<<ListboxSelect>>", lambda e: self.on_task_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.task_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.task_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save", command=self.task_save, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Run Now", command=self.task_run_now, style="Colored.TButton").pack(side="left", padx=6)

        right = ttk.LabelFrame(outer, text="Task details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.selected_task_idx: Optional[int] = None

        self.tv_name = tk.StringVar()
        self.tv_enabled = tk.BooleanVar(value=True)
        self.tv_profile = tk.StringVar()
        self.tv_preset = tk.StringVar()
        self.tv_hour = tk.StringVar(value="0")
        self.tv_minute = tk.StringVar(value="0")
        self.tv_dry = tk.BooleanVar(value=False)
        self.tv_mode = tk.StringVar(value="enabled")  # enabled or selected

        r = 0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.tv_name, width=46).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Checkbutton(form, text="Enabled", variable=self.tv_enabled).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Profile").grid(row=r, column=0, sticky="w")
        self.cmb_task_profile = ttk.Combobox(form, textvariable=self.tv_profile, state="readonly", width=43)
        self.cmb_task_profile.grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Preset").grid(row=r, column=0, sticky="w")
        self.cmb_task_preset = ttk.Combobox(form, textvariable=self.tv_preset, state="readonly", width=43)
        self.cmb_task_preset.grid(row=r, column=1, sticky="w", pady=2); r+=1

        days_box = ttk.LabelFrame(form, text="Days")
        days_box.grid(row=r, column=0, columnspan=2, sticky="w", pady=(8,6))
        self._days_keys = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
        self._days_vars = {k: tk.BooleanVar(value=False) for k in self._days_keys}
        for i, k in enumerate(self._days_keys):
            ttk.Checkbutton(days_box, text=k, variable=self._days_vars[k]).grid(row=0, column=i, sticky="w", padx=6, pady=4)
        r += 1

        time_box = ttk.Frame(form)
        time_box.grid(row=r, column=0, columnspan=2, sticky="w", pady=(6,2))
        ttk.Label(time_box, text="Hour (0-23)").grid(row=0, column=0, sticky="w")
        ttk.Entry(time_box, textvariable=self.tv_hour, width=6).grid(row=0, column=1, sticky="w", padx=(6,16))
        ttk.Label(time_box, text="Minute (0-59)").grid(row=0, column=2, sticky="w")
        ttk.Entry(time_box, textvariable=self.tv_minute, width=6).grid(row=0, column=3, sticky="w", padx=(6,0))

        ttk.Checkbutton(form, text="Dry run (log only, no upload)", variable=self.tv_dry).grid(row=r+1, column=1, sticky="w", pady=(6,2))

        mode_box = ttk.LabelFrame(form, text="Mappings used by this task")
        mode_box.grid(row=r+2, column=0, columnspan=2, sticky="w", pady=(8,6))
        ttk.Radiobutton(mode_box, text="Use globally enabled mappings", variable=self.tv_mode, value="enabled").grid(row=0, column=0, sticky="w", padx=6, pady=4)
        ttk.Radiobutton(mode_box, text="Use selected mappings (choose below)", variable=self.tv_mode, value="selected").grid(row=0, column=1, sticky="w", padx=6, pady=4)

        self.lst_task_mappings = tk.Listbox(mode_box, height=6, width=52, selectmode="extended", exportselection=False)
        self.lst_task_mappings.grid(row=1, column=0, columnspan=2, sticky="w", padx=6, pady=6)
        style_listbox(self.lst_task_mappings)

        self._refresh_task_combos()

    def _refresh_task_combos(self):
        self.cmb_task_profile["values"] = [p.name for p in self.profiles]
        self.cmb_task_preset["values"] = self._list_presets()
        self.lst_task_mappings.delete(0, "end")
        for m in self.mappings:
            self.lst_task_mappings.insert("end", m.name)
        if self.profiles and not self.tv_profile.get():
            self.tv_profile.set(self.profiles[0].name)
        presets = self._list_presets()
        if presets and (self.tv_preset.get() not in presets):
            self.tv_preset.set(presets[0])

    def _list_presets(self) -> List[str]:
        if not self.presets_dir.exists():
            return []
        return [p.name for p in sorted(self.presets_dir.iterdir()) if p.is_dir()]

    def refresh_tasks_list(self):
        self.lst_tasks.delete(0, "end")
        for t in self.tasks_obj.get("tasks", []):
            flag = "ON" if t.get("enabled", True) else "OFF"
            days = ",".join(t.get("days", []))
            hh = int(t.get("hour", 0)); mm = int(t.get("minute", 0))
            mode = t.get("mapping_mode", "enabled")
            self.lst_tasks.insert("end", f"[{flag}] {t.get('name','Task')} | {days} {hh:02d}:{mm:02d} | {t.get('profile','')} -> {t.get('preset','')} | maps={mode}")

    def on_task_select(self):
        sel = self.lst_tasks.curselection()
        if not sel:
            return
        idx = int(sel[0])
        self.selected_task_idx = idx
        t = self.tasks_obj.get("tasks", [])[idx]

        self.tv_name.set(t.get("name", ""))
        self.tv_enabled.set(bool(t.get("enabled", True)))
        self.tv_profile.set(t.get("profile", ""))
        self.tv_preset.set(t.get("preset", ""))
        self.tv_hour.set(str(t.get("hour", 0)))
        self.tv_minute.set(str(t.get("minute", 0)))
        self.tv_dry.set(bool(t.get("dry_run", False)))
        self.tv_mode.set(t.get("mapping_mode", "enabled"))

        days = set(t.get("days", []))
        for k in self._days_keys:
            self._days_vars[k].set(k in days)

        selected_names = set(t.get("mappings", []))
        self.lst_task_mappings.selection_clear(0, "end")
        for i, m in enumerate(self.mappings):
            if m.name in selected_names:
                self.lst_task_mappings.selection_set(i)

    def task_new(self):
        tasks = self.tasks_obj.get("tasks", [])
        n = f"Task_{len(tasks)+1}"
        default_profile = self.profiles[0].name if self.profiles else ""
        presets = self._list_presets()
        default_preset = presets[0] if presets else ""

        tasks.append({
            "name": n,
            "enabled": True,
            "profile": default_profile,
            "preset": default_preset,
            "days": ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"],
            "hour": 0,
            "minute": 0,
            "dry_run": False,
            "mapping_mode": "enabled",
            "mappings": [],
            "last_run": ""
        })
        self.tasks_obj["tasks"] = tasks
        save_tasks(self.tasks_obj)
        self.refresh_tasks_list()

        idx = len(tasks) - 1
        self.lst_tasks.selection_clear(0, "end")
        self.lst_tasks.selection_set(idx)
        self.lst_tasks.see(idx)
        self.on_task_select()

    def task_delete(self):
        if self.selected_task_idx is None:
            messagebox.showwarning("No task", "Select a task.")
            return
        t = self.tasks_obj.get("tasks", [])[self.selected_task_idx]
        if not messagebox.askyesno("Delete", f"Delete task '{t.get('name','Task')}'?"):
            return
        del self.tasks_obj["tasks"][self.selected_task_idx]
        self.selected_task_idx = None
        save_tasks(self.tasks_obj)
        self.refresh_tasks_list()

    def task_save(self):
        if self.selected_task_idx is None:
            messagebox.showwarning("No task", "Select a task.")
            return
        try:
            hh = int((self.tv_hour.get() or "0").strip())
            mm = int((self.tv_minute.get() or "0").strip())
            if hh < 0 or hh > 23 or mm < 0 or mm > 59:
                raise ValueError()
        except Exception:
            messagebox.showerror("Invalid time", "Hour must be 0-23 and Minute must be 0-59.")
            return

        days = [k for k in self._days_keys if self._days_vars[k].get()]
        if not days:
            messagebox.showerror("Invalid days", "Select at least one day.")
            return

        mode = (self.tv_mode.get() or "enabled").strip()
        selected_mapping_names: List[str] = []
        if mode == "selected":
            sel = self.lst_task_mappings.curselection()
            selected_mapping_names = [self.mappings[i].name for i in sel] if sel else []
            if not selected_mapping_names:
                messagebox.showerror("No mappings", "Select at least one mapping, or switch to enabled mappings.")
                return

        t = self.tasks_obj["tasks"][self.selected_task_idx]
        t["name"] = self.tv_name.get().strip() or "Task"
        t["enabled"] = bool(self.tv_enabled.get())
        t["profile"] = (self.tv_profile.get() or "").strip()
        t["preset"] = (self.tv_preset.get() or "").strip()
        t["days"] = days
        t["hour"] = hh
        t["minute"] = mm
        t["dry_run"] = bool(self.tv_dry.get())
        t["mapping_mode"] = mode
        t["mappings"] = selected_mapping_names

        save_tasks(self.tasks_obj)
        self.refresh_tasks_list()
        messagebox.showinfo("Saved", "Task saved.")

    def task_run_now(self):
        # runs currently selected task from the Tasks tab (or dashboard button)
        idx = self.selected_task_idx
        if idx is None:
            messagebox.showwarning("No task", "Select a task in the Tasks tab.")
            return
        t = self.tasks_obj.get("tasks", [])[idx]
        if not messagebox.askyesno("Run now", f"Run task '{t.get('name','Task')}' now?"):
            return
        ok = self._run_upload_for_task(t, dry_run=bool(t.get("dry_run", False)))
        if ok:
            self.log.info(f"[TASK] Run-now complete: {t.get('name','Task')}")
            messagebox.showinfo("Done", "Task completed.")
        else:
            messagebox.showerror("Failed", "Task failed. Check Log.")

    # ---------------- Profiles ----------------
    def _build_profiles(self):
        f = self.tab_profiles
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Profiles")
        left.pack(side="left", fill="both", expand=False)

        self.lst_profiles = tk.Listbox(left, width=34, height=20, exportselection=False)
        self.lst_profiles.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_profiles)
        self.lst_profiles.bind("<<ListboxSelect>>", lambda e: self.on_profile_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.profile_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.profile_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save", command=self.profile_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Profile details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.selected_profile_idx: Optional[int] = None

        self.v_name = tk.StringVar(); self.v_host = tk.StringVar(); self.v_port = tk.StringVar(value="21")
        self.v_user = tk.StringVar(); self.v_pass = tk.StringVar(); self.v_tls = tk.BooleanVar(value=False)
        self.v_root = tk.StringVar(value="/dayzstandalone")

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_name, width=46).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Host").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_host, width=46).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Port").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_port, width=12).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Username").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_user, width=46).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Password").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_pass, width=46, show="*").grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Checkbutton(form, text="Use FTPS (FTP over TLS)", variable=self.v_tls).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Label(form, text="Remote root").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.v_root, width=46).grid(row=r, column=1, sticky="w", pady=2); r+=1

    def refresh_profiles_list(self):
        self.lst_profiles.delete(0, "end")
        for p in self.profiles:
            self.lst_profiles.insert("end", p.name)
        self._refresh_task_combos()

    def on_profile_select(self):
        sel = self.lst_profiles.curselection()
        if not sel:
            return
        idx = int(sel[0])
        self.selected_profile_idx = idx
        p = self.profiles[idx]
        self.v_name.set(p.name); self.v_host.set(p.host); self.v_port.set(str(p.port))
        self.v_user.set(p.username); self.v_pass.set(p.password); self.v_tls.set(p.tls); self.v_root.set(p.root)

    def profile_new(self):
        n = "Profile_" + str(len(self.profiles) + 1)
        self.profiles.append(Profile(n, "", 21, "", "", False, "/dayzstandalone"))
        save_profiles(self.profiles)
        self.refresh_profiles_list()
        idx = len(self.profiles)-1
        self.lst_profiles.selection_clear(0, "end")
        self.lst_profiles.selection_set(idx)
        self.lst_profiles.see(idx)
        self.on_profile_select()

    def profile_delete(self):
        if self.selected_profile_idx is None:
            messagebox.showwarning("No profile", "Select a profile.")
            return
        p = self.profiles[self.selected_profile_idx]
        if not messagebox.askyesno("Delete", f"Delete profile '{p.name}'?"):
            return
        del self.profiles[self.selected_profile_idx]
        self.selected_profile_idx = None
        save_profiles(self.profiles)
        self.refresh_profiles_list()

    def profile_save(self):
        if self.selected_profile_idx is None:
            messagebox.showwarning("No profile", "Select a profile.")
            return
        try:
            port = int((self.v_port.get() or "21").strip())
        except ValueError:
            messagebox.showerror("Invalid", "Port must be a number.")
            return
        self.profiles[self.selected_profile_idx] = Profile(
            name=self.v_name.get().strip() or "Unnamed",
            host=self.v_host.get().strip(),
            port=port,
            username=self.v_user.get().strip(),
            password=self.v_pass.get(),
            tls=bool(self.v_tls.get()),
            root=self.v_root.get().strip() or "/dayzstandalone"
        )
        save_profiles(self.profiles)
        self.refresh_profiles_list()
        messagebox.showinfo("Saved", "Profile saved.")

    def selected_profile_for_test(self) -> Optional[Profile]:
        if self.selected_profile_idx is None:
            return None
        if self.selected_profile_idx < 0 or self.selected_profile_idx >= len(self.profiles):
            return None
        return self.profiles[self.selected_profile_idx]

    def test_conn_selected_profile(self):
        p = self.selected_profile_for_test()
        if not p:
            messagebox.showwarning("No profile", "Select a profile in the Profiles tab.")
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

    # ---------------- Mappings ----------------
    def _build_mappings(self):
        f = self.tab_mappings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Mappings")
        left.pack(side="left", fill="both", expand=False)

        self.lst_mappings = tk.Listbox(left, width=62, height=20, exportselection=False)
        self.lst_mappings.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_mappings)
        self.lst_mappings.bind("<<ListboxSelect>>", lambda e: self.on_mapping_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.mapping_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.mapping_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save", command=self.mapping_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Mapping details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.selected_mapping_idx: Optional[int] = None
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
        self._refresh_task_combos()

    def on_mapping_select(self):
        sel = self.lst_mappings.curselection()
        if not sel:
            return
        idx = int(sel[0])
        self.selected_mapping_idx = idx
        m = self.mappings[idx]
        self.m_name.set(m.name); self.m_enabled.set(m.enabled)
        self.m_local.set(m.local_relpath); self.m_remote.set(m.remote_path); self.m_backup.set(m.backup_before_overwrite)

    def mapping_new(self):
        self.mappings.append(Mapping(f"Mapping_{len(self.mappings)+1}", True, "", "", True))
        save_mappings(self.mappings)
        self.refresh_mappings_list()

    def mapping_delete(self):
        if self.selected_mapping_idx is None:
            messagebox.showwarning("No mapping", "Select a mapping.")
            return
        m = self.mappings[self.selected_mapping_idx]
        if not messagebox.askyesno("Delete", f"Delete mapping '{m.name}'?"):
            return
        del self.mappings[self.selected_mapping_idx]
        self.selected_mapping_idx = None
        save_mappings(self.mappings)
        self.refresh_mappings_list()

    def mapping_save(self):
        if self.selected_mapping_idx is None:
            messagebox.showwarning("No mapping", "Select a mapping.")
            return
        self.mappings[self.selected_mapping_idx] = Mapping(
            name=self.m_name.get().strip() or "Unnamed",
            enabled=bool(self.m_enabled.get()),
            local_relpath=self.m_local.get().strip(),
            remote_path=self.m_remote.get().strip(),
            backup_before_overwrite=bool(self.m_backup.get()),
        )
        save_mappings(self.mappings)
        self.refresh_mappings_list()
        messagebox.showinfo("Saved", "Mapping saved.")

    # ---------------- Settings ----------------
    def _build_settings(self):
        f = self.tab_settings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        frm = ttk.LabelFrame(outer, text="App settings")
        frm.pack(fill="x", expand=False)

        self.s_timeout = tk.StringVar(value=str(self.timeout))
        self.s_tick = tk.StringVar(value=str(self.tick_seconds))
        self.s_presets = tk.StringVar(value=str(self.presets_dir))
        self.s_autostart = tk.BooleanVar(value=self.auto_start)

        r=0
        ttk.Label(frm, text="FTP timeout (seconds)").grid(row=r, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.s_timeout, width=10).grid(row=r, column=1, sticky="w", pady=6)
        r+=1

        ttk.Label(frm, text="Scheduler tick (seconds)").grid(row=r, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.s_tick, width=10).grid(row=r, column=1, sticky="w", pady=6)
        r+=1

        ttk.Label(frm, text="Presets folder").grid(row=r, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(frm, textvariable=self.s_presets, width=72).grid(row=r, column=1, sticky="w", pady=6)
        ttk.Button(frm, text="Browse", command=self.browse_presets, style="Colored.TButton").grid(row=r, column=2, sticky="w", padx=8)
        r+=1

        ttk.Checkbutton(frm, text="Auto-start scheduler on launch", variable=self.s_autostart).grid(row=r, column=1, sticky="w", pady=6)
        r+=1

        ttk.Button(frm, text="Save Settings", command=self.save_settings_ui, style="Colored.TButton").grid(row=r, column=1, sticky="w", pady=10)

        note = ttk.LabelFrame(outer, text="Notes")
        note.pack(fill="both", expand=True, pady=(10,0))
        t = tk.Text(note, wrap="word", height=10)
        t.pack(fill="both", expand=True, padx=8, pady=8)
        style_text_widget(t)
        t.insert("1.0",
                 "Created by Danny van den Brande\n\n"
                 "AutomationZ Scheduler is free and open-source software.\n\n"
                 "If this tool helps you automate server tasks, save time,\n"
                 "or manage multiple servers more easily,\n"
                 "consider supporting development with a donation.\n\n"
                 "Donations are optional, but appreciated and help\n"
                 "support ongoing development and improvements.\n\n"
                 "Support link:\n"
                 "https://ko-fi.com/dannyvandenbrande\n")
        t.configure(state="disabled")

    def browse_presets(self):
        # basic directory picker without extra deps
        try:
            from tkinter import filedialog
            p = filedialog.askdirectory(initialdir=str(self.presets_dir))
            if p:
                self.s_presets.set(p)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def save_settings_ui(self):
        try:
            timeout = int((self.s_timeout.get() or "20").strip())
            tick = int((self.s_tick.get() or "20").strip())
            if tick < 5:
                messagebox.showerror("Invalid", "Tick seconds should be 5 or more.")
                return
        except Exception:
            messagebox.showerror("Invalid", "Timeout and Tick must be numbers.")
            return

        self.timeout = timeout
        self.tick_seconds = tick
        self.presets_dir = pathlib.Path(self.s_presets.get()).expanduser().resolve()
        self.auto_start = bool(self.s_autostart.get())

        self.settings["app"]["timeout_seconds"] = self.timeout
        self.settings["app"]["tick_seconds"] = self.tick_seconds
        self.settings["app"]["presets_dir"] = str(self.presets_dir)
        self.settings["app"]["auto_start"] = self.auto_start
        save_settings(self.settings)

        self._set_state_label()
        self._refresh_task_combos()
        self.log.info("Settings saved.")
        messagebox.showinfo("Saved", "Settings saved.")

    # ---------------- Scheduler Loop ----------------
    def _tick(self):
        try:
            if self.scheduler_running:
                self._check_tasks()
        except Exception as e:
            self.log.error("Scheduler error: " + str(e))
            self.log.error(traceback.format_exc())
        self.after(max(1000, self.tick_seconds * 1000), self._tick)

    def _check_tasks(self):
        days_map = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]
        now = datetime.datetime.now()
        today = days_map[now.weekday()]
        stamp_minute = now.strftime("%Y-%m-%d %H:%M")

        for t in self.tasks_obj.get("tasks", []):
            if not t.get("enabled", True):
                continue
            if today not in t.get("days", []):
                continue
            try:
                if int(t.get("hour", -1)) != now.hour or int(t.get("minute", -1)) != now.minute:
                    continue
            except Exception:
                continue
            if (t.get("last_run") or "") == stamp_minute:
                continue

            name = t.get("name","Task")
            dry = bool(t.get("dry_run", False))
            self.log.info(f"[TASK] Trigger: {name} ({today} {now.strftime('%H:%M')})")
            ok = self._run_upload_for_task(t, dry_run=dry)
            if ok:
                t["last_run"] = stamp_minute
                save_tasks(self.tasks_obj)
                self.log.info(f"[TASK] Completed: {name}")
            else:
                self.log.warn(f"[TASK] Failed: {name}")

    def _run_upload_for_task(self, task: dict, dry_run: bool=False) -> bool:
        profile_name = (task.get("profile","") or "").strip()
        preset_name = (task.get("preset","") or "").strip()
        mode = (task.get("mapping_mode", "enabled") or "enabled").strip()
        selected_names = set(task.get("mappings", []) or [])

        p = next((x for x in self.profiles if x.name == profile_name), None)
        if not p:
            self.log.error(f"[TASK] Profile not found: {profile_name}")
            return False

        preset_dir = self.presets_dir / preset_name
        if not preset_dir.exists():
            self.log.error(f"[TASK] Preset not found: {preset_dir}")
            return False

        use_mappings = [m for m in self.mappings if (m.name in selected_names)] if mode == "selected" else [m for m in self.mappings if m.enabled]
        if not use_mappings:
            self.log.error("[TASK] No mappings to run (check enabled/selected).")
            return False

        # verify local files exist
        missing = [m.local_relpath for m in use_mappings if not (preset_dir / m.local_relpath).exists()]
        if missing:
            self.log.error("[TASK] Missing files in preset:\n" + "\n".join(missing))
            return False

        root = norm_remote(p.root or "/")
        cli = FTPClient(p, self.timeout)

        try:
            if dry_run:
                for m in use_mappings:
                    local_file = preset_dir / m.local_relpath
                    remote_full = "/" + (root.rstrip("/") + "/" + norm_remote(m.remote_path)).strip("/")
                    self.log.info(f"[TASK][DRY] Would upload: {local_file} -> {remote_full}")
                return True

            cli.connect()

            for m in use_mappings:
                local_file = preset_dir / m.local_relpath
                remote_full = "/" + (root.rstrip("/") + "/" + norm_remote(m.remote_path)).strip("/")

                if m.backup_before_overwrite:
                    # backups stored inside logs folder by date (simple)
                    bdir = LOGS_DIR / "backups" / p.name / preset_name / now_stamp()
                    bpath = bdir / m.local_relpath
                    ok = cli.download(remote_full, bpath)
                    if ok:
                        self.log.info(f"[TASK] Backup OK: {remote_full} -> {bpath}")
                    else:
                        self.log.warn(f"[TASK] Backup skipped/failed: {remote_full}")

                cli.upload(local_file, remote_full)
                self.log.info(f"[TASK] Uploaded: {local_file} -> {remote_full}")

            return True
        except Exception as e:
            self.log.error("[TASK] Upload failed: " + str(e))
            self.log.error(traceback.format_exc())
            return False
        finally:
            cli.close()

def main():
    for p in [CONFIG_DIR, LOGS_DIR]:
        p.mkdir(parents=True, exist_ok=True)
    App().mainloop()

if __name__ == "__main__":
    main()
