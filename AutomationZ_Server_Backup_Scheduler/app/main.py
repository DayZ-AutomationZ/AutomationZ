#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import urllib.request
import pathlib
import datetime
import traceback
import shutil
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

import ftplib

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

APP_NAME = "AutomationZ Server Backup Scheduler"
APP_VERSION = "1.0.3"

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
DATA_DIR = BASE_DIR / "backups"

PROFILES_PATH = CONFIG_DIR / "profiles.json"
JOBS_PATH = CONFIG_DIR / "backup_jobs.json"
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

DAYS = ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"]

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def norm_remote(path: str) -> str:
    # IMPORTANT: use a single escaped backslash in the python string literal: "\\"
    p = (path or "").replace("\\", "/" ).replace("\r", "").replace("\n", "")
    if not p.startswith("/"):
        p = "/" + p
    if len(p) > 1 and p.endswith("/"):
        p = p[:-1]
    return p

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
        self.widget = widget

    def _append(self, line: str):
        self.widget.configure(state="normal")
        self.widget.insert("end", line + "\n")
        self.widget.see("end")
        self.widget.configure(state="disabled")

    def info(self, msg: str): self._append("[INFO] " + msg)
    def warn(self, msg: str): self._append("[WARN] " + msg)
    def error(self, msg: str): self._append("[ERROR] " + msg)

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
class BackupJob:
    name: str
    enabled: bool
    profile: str
    mode: str              # snapshot | mirror
    remote_source: str     # file or folder
    local_target: str      # base folder
    days: List[str]
    hour: int
    minute: int
    include_subdirs: bool
    keep_last: int
    dry_run: bool

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

def load_jobs() -> List[BackupJob]:
    obj = load_json(JOBS_PATH, {"jobs": []})
    jobs: List[BackupJob] = []
    for j in obj.get("jobs", []):
        jobs.append(BackupJob(
            name=j.get("name","Unnamed Job"),
            enabled=bool(j.get("enabled", True)),
            profile=j.get("profile",""),
            mode=j.get("mode","snapshot"),
            remote_source=j.get("remote_source","/"),
            local_target=j.get("local_target", str(DATA_DIR)),
            days=list(j.get("days", ["Sat"])),
            hour=int(j.get("hour", 0)),
            minute=int(j.get("minute", 0)),
            include_subdirs=bool(j.get("include_subdirs", True)),
            keep_last=int(j.get("keep_last", 10)),
            dry_run=bool(j.get("dry_run", False)),
        ))
    return jobs

def save_jobs(jobs: List[BackupJob]) -> None:
    save_json(JOBS_PATH, {"jobs":[j.__dict__ for j in jobs]})

def load_settings() -> Dict[str, Any]:
    return load_json(SETTINGS_PATH, {
        "app": {
            "timeout_seconds": 30,
            "tick_seconds": 20,
            "auto_start": False
        }
    })

class FTPClient:
    def __init__(self, profile: Profile, timeout: int):
        self.p = profile
        self.timeout = timeout
        self.ftp: Optional[ftplib.FTP] = None

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

    def pwd(self) -> str:
        return self.ftp.pwd() if self.ftp else ""

    def is_dir(self, path: str) -> bool:
        cur = self.ftp.pwd()
        try:
            self.ftp.cwd(path)
            self.ftp.cwd(cur)
            return True
        except Exception:
            try:
                self.ftp.cwd(cur)
            except Exception:
                pass
            return False

    def list_dir(self, path: str) -> List[str]:
        items: List[str] = []
        try:
            for name, facts in self.ftp.mlsd(path):
                if name in (".", ".."):
                    continue
                items.append(name)
            return items
        except Exception:
            pass
        try:
            raw = self.ftp.nlst(path)
            for r in raw:
                r = r.replace("\\", "/")
                items.append(r.split("/")[-1])
            seen=set(); out=[]
            for x in items:
                if x not in seen:
                    seen.add(x); out.append(x)
            return out
        except Exception:
            return []

    def download_file(self, remote_full: str, local_path: pathlib.Path):
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            self.ftp.retrbinary("RETR " + remote_full, f.write)

def weekday_now() -> str:
    return DAYS[datetime.datetime.now().weekday()]

def safe_join_local(root: pathlib.Path, rel: str) -> pathlib.Path:
    rel = rel.replace("/", os.sep).lstrip(os.sep)
    out = (root / rel).resolve()
    rr = root.resolve()
    if out != rr and rr not in out.parents:
        raise ValueError("Unsafe path: " + rel)
    return out

class App(tk.Tk):
    def _discord_post(self, text: str) -> None:
        """Send a Discord webhook message if configured."""
        try:
            dcfg = self.settings.get("discord", {}) if isinstance(self.settings, dict) else {}
            url = (dcfg.get("webhook_url", "") or "").strip()
            if not url:
                return
            payload = json.dumps({"content": text}).encode("utf-8")
            req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json", "User-Agent": "AutomationZ-Backup/1.0 (+https://github.com/DayZ-AutomationZ)"})
            urllib.request.urlopen(req, timeout=10).read()
        except Exception as e:
            try:
                self.log.warn(f"Discord webhook failed: {e}")
            except Exception:
                pass

    def __init__(self):
        super().__init__()
        self.style = apply_dark_theme(self)
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1040x700")
        self.minsize(980, 640)

        for p in (CONFIG_DIR, DATA_DIR):
            p.mkdir(parents=True, exist_ok=True)

        self.settings = load_settings()
        self.timeout = int(self.settings.get("app",{}).get("timeout_seconds", 30))
        self.tick_seconds = int(self.settings.get("app",{}).get("tick_seconds", 20))
        self.auto_start = bool(self.settings.get("app",{}).get("auto_start", False))

        self.profiles, self.active_profile = load_profiles()
        self.jobs = load_jobs()

        self.scheduler_running = False
        self.last_run_key: Dict[str, str] = {}

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_dashboard = ttk.Frame(nb)
        self.tab_jobs = ttk.Frame(nb)
        self.tab_profiles = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        self.tab_help = ttk.Frame(nb)

        nb.add(self.tab_dashboard, text="Dashboard")
        nb.add(self.tab_jobs, text="Backup Jobs")
        nb.add(self.tab_profiles, text="Profiles")
        nb.add(self.tab_settings, text="Settings")
        nb.add(self.tab_help, text="Help")

        log_box = ttk.LabelFrame(self, text="Log")
        log_box.pack(fill="both", expand=False, padx=10, pady=8)
        self.log_text = tk.Text(log_box, height=12, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        style_text_widget(self.log_text)
        self.log = Logger(self.log_text)

        self._build_dashboard()
        self._build_jobs()
        self._build_profiles()
        self._build_settings()
        self._build_help()

        self.refresh_profiles_combo()
        self.refresh_profiles_list()
        self.refresh_jobs_list()
        self.refresh_status()

        if self.auto_start:
            self.start_scheduler()

    # Dashboard
    def _build_dashboard(self):
        f = self.tab_dashboard
        top = ttk.Frame(f); top.pack(fill="x", padx=12, pady=10)

        self.lbl_status = ttk.Label(top, text="Scheduler: STOPPED")
        self.lbl_status.grid(row=0, column=0, sticky="w")

        ttk.Button(top, text="Start Scheduler", command=self.start_scheduler, style="Colored.TButton").grid(row=0, column=1, padx=8)
        ttk.Button(top, text="Stop Scheduler", command=self.stop_scheduler, style="Colored.TButton").grid(row=0, column=2, padx=8)
        ttk.Button(top, text="Run Selected Job Now", command=self.run_selected_job_now, style="Colored.TButton").grid(row=0, column=3, padx=8)

        mid = ttk.LabelFrame(f, text="Jobs")
        mid.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.lst_dash_jobs = tk.Listbox(mid, height=18, exportselection=False)
        self.lst_dash_jobs.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_dash_jobs)

        bot = ttk.Frame(f); bot.pack(fill="x", padx=12, pady=(0,12))
        ttk.Label(bot, text="Test connection profile:").pack(side="left")
        self.cmb_test_profile = ttk.Combobox(bot, state="readonly", width=30)
        self.cmb_test_profile.pack(side="left", padx=8)
        ttk.Button(bot, text="Test Connection", command=self.test_conn, style="Colored.TButton").pack(side="left", padx=8)

    def refresh_status(self):
        self.lbl_status.configure(text="Scheduler: RUNNING" if self.scheduler_running else "Scheduler: STOPPED")

    def start_scheduler(self):
        if self.scheduler_running:
            return
        self.scheduler_running = True
        self.refresh_status()
        self.log.info("Scheduler started.")
        self.after(500, self._tick)

    def stop_scheduler(self):
        self.scheduler_running = False
        self.refresh_status()
        self.log.warn("Scheduler stopped.")

    def _tick(self):
        if not self.scheduler_running:
            return
        try:
            self.check_and_run_due_jobs()
        except Exception as e:
            self.log.error("Scheduler tick error: " + str(e))
            self.log.error(traceback.format_exc())
        self.after(max(1, self.tick_seconds) * 1000, self._tick)

    def check_and_run_due_jobs(self):
        now = datetime.datetime.now()
        day = weekday_now()
        hh = now.hour
        mm = now.minute
        key_time = f"{day}-{hh:02d}:{mm:02d}"
        for job in self.jobs:
            if not job.enabled:
                continue
            if day not in job.days:
                continue
            if job.hour != hh or job.minute != mm:
                continue
            last = self.last_run_key.get(job.name)
            if last == key_time:
                continue
            self.last_run_key[job.name] = key_time
            self.run_job(job)

    def run_selected_job_now(self):
        idx = self._sel_index(self.lst_dash_jobs)
        if idx is None:
            messagebox.showwarning("No job", "Select a job in the list.")
            return
        job = self.jobs[idx]
        if not messagebox.askyesno("Run now", f"Run job '{job.name}' now?"):
            return
        self.run_job(job)

    def get_profile(self, name: str) -> Optional[Profile]:
        for p in self.profiles:
            if p.name == name:
                return p
        return None

    def run_job(self, job: BackupJob):
        p = self.get_profile(job.profile)
        if not p:
            self.log.error(f"Job '{job.name}': profile '{job.profile}' not found.")
            return

        remote_root = norm_remote(p.root or "/")
        src = (job.remote_source or "").strip().replace("\r", "").replace("\n", "")
        if src.startswith("/"):
            remote_full = norm_remote(src)
        else:
            remote_full = norm_remote(remote_root.rstrip("/") + "/" + src)

        local_base = pathlib.Path(job.local_target).expanduser()
        local_base.mkdir(parents=True, exist_ok=True)

        if job.mode.lower() == "snapshot":
            dest_root = local_base / p.name / job.name / now_stamp()
        else:
            dest_root = local_base / p.name / job.name / "MIRROR"

        self.log.info(f"JOB: {job.name} | mode={job.mode} | profile={p.name}")
        dcfg = self.settings.get("discord", {}) if isinstance(self.settings, dict) else {}
        if dcfg.get("notify_start", True):
            self._discord_post(f"⏳ Backup started: {job.name} ({p.name})")
        self.log.info(f"Remote: {remote_full}")
        self.log.info(f"Local : {dest_root}")
        if job.dry_run:
            self.log.warn("Dry run enabled: no files will be downloaded.")

        cli = FTPClient(p, self.timeout)
        try:
            cli.connect()
            if cli.is_dir(remote_full):
                self._download_dir(cli, remote_full, dest_root, job, rel_prefix="")
            else:
                rel_name = remote_full.split("/")[-1]
                target = safe_join_local(dest_root, rel_name)
                if not job.dry_run:
                    cli.download_file(remote_full, target)
                self.log.info(f"Downloaded file: {remote_full} -> {target}")

            if job.mode.lower() == "snapshot" and job.keep_last and job.keep_last > 0:
                self._cleanup_snapshots(local_base / p.name / job.name, job.keep_last)

            self.log.info(f"JOB DONE: {job.name}")
            dcfg = self.settings.get("discord", {}) if isinstance(self.settings, dict) else {}
            if dcfg.get("notify_success", True):
                self._discord_post(f"✅ Backup done: {job.name} ({p.name})")
        except Exception as e:
            self.log.error(f"JOB FAILED: {job.name} -> {e}")
            dcfg = self.settings.get("discord", {}) if isinstance(self.settings, dict) else {}
            if dcfg.get("notify_failure", True):
                self._discord_post(f"❌ Backup failed: {job.name} ({job.profile}) — {e}")
            self.log.error(traceback.format_exc())
        finally:
            cli.close()

    def _cleanup_snapshots(self, job_dir: pathlib.Path, keep_last: int):
        if not job_dir.exists():
            return
        snaps = [d for d in job_dir.iterdir() if d.is_dir()]
        snaps.sort(key=lambda p: p.name, reverse=True)
        for d in snaps[keep_last:]:
            try:
                shutil.rmtree(d)
                self.log.info(f"Cleanup: removed old snapshot {d}")
            except Exception:
                self.log.warn(f"Cleanup: could not remove {d}")

    def _download_dir(self, cli: FTPClient, remote_dir: str, local_root: pathlib.Path, job: BackupJob, rel_prefix: str):
        self.log.info(f"Entering folder: {remote_dir}")
        items = cli.list_dir(remote_dir)
        for name in items:
            remote_child = remote_dir.rstrip("/") + "/" + name
            rel_child = (rel_prefix + "/" + name).lstrip("/")
            if job.include_subdirs and cli.is_dir(remote_child):
                self._download_dir(cli, remote_child, local_root, job, rel_child)
            else:
                target = safe_join_local(local_root, rel_child)
                if not job.dry_run:
                    cli.download_file(remote_child, target)
                self.log.info(f"Downloaded: {remote_child} -> {target}")

    def test_conn(self):
        name = (self.cmb_test_profile.get() or "").strip()
        p = self.get_profile(name)
        if not p:
            messagebox.showwarning("No profile", "Select a profile.")
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

    # Jobs UI
    def _build_jobs(self):
        f = self.tab_jobs
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Backup Jobs")
        left.pack(side="left", fill="both", expand=False)

        self.lst_jobs = tk.Listbox(left, width=52, height=18, exportselection=False)
        self.lst_jobs.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_jobs)
        self.lst_jobs.bind("<<ListboxSelect>>", lambda e: self.on_job_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.job_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.job_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.job_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Job details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.j_name = tk.StringVar()
        self.j_enabled = tk.BooleanVar(value=True)
        self.j_profile = tk.StringVar()
        self.j_mode = tk.StringVar(value="snapshot")
        self.j_remote = tk.StringVar(value="/")
        self.j_local = tk.StringVar(value=str(DATA_DIR))
        self.j_hour = tk.StringVar(value="0")
        self.j_min = tk.StringVar(value="0")
        self.j_subdirs = tk.BooleanVar(value=True)
        self.j_keep = tk.StringVar(value="10")
        self.j_dry = tk.BooleanVar(value=False)

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.j_name, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Checkbutton(form, text="Enabled", variable=self.j_enabled).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Profile").grid(row=r, column=0, sticky="w")
        self.cmb_job_profile = ttk.Combobox(form, state="readonly", textvariable=self.j_profile, width=30)
        self.cmb_job_profile.grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Mode").grid(row=r, column=0, sticky="w")
        self.cmb_job_mode = ttk.Combobox(form, state="readonly", textvariable=self.j_mode, values=["snapshot","mirror"], width=18)
        self.cmb_job_mode.grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Remote source path (file or folder)").grid(row=r, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.j_remote, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Local destination folder").grid(row=r, column=0, sticky="w")
        row_local = ttk.Frame(form); row_local.grid(row=r, column=1, sticky="w", pady=2)
        ttk.Entry(row_local, textvariable=self.j_local, width=46).pack(side="left")
        ttk.Button(row_local, text="Browse", command=self.browse_local, style="Colored.TButton").pack(side="left", padx=6)
        r+=1

        ttk.Label(form, text="Days").grid(row=r, column=0, sticky="nw")
        days_frame = ttk.Frame(form); days_frame.grid(row=r, column=1, sticky="w", pady=2)
        self.day_vars: Dict[str, tk.BooleanVar] = {}
        for i, d in enumerate(DAYS):
            v = tk.BooleanVar(value=(d == "Sat"))
            self.day_vars[d] = v
            ttk.Checkbutton(days_frame, text=d, variable=v).grid(row=0, column=i, sticky="w", padx=2)
        r+=1

        ttk.Label(form, text="Time (Hour:Minute)").grid(row=r, column=0, sticky="w")
        time_row = ttk.Frame(form); time_row.grid(row=r, column=1, sticky="w", pady=2)
        ttk.Entry(time_row, textvariable=self.j_hour, width=5).pack(side="left")
        ttk.Label(time_row, text=":").pack(side="left")
        ttk.Entry(time_row, textvariable=self.j_min, width=5).pack(side="left")
        r+=1

        ttk.Checkbutton(form, text="Include subfolders (if remote is a folder)", variable=self.j_subdirs).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Keep last snapshots (snapshot mode)").grid(row=r, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.j_keep, width=8).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Checkbutton(form, text="Dry run (log only, no download)", variable=self.j_dry).grid(row=r, column=1, sticky="w", pady=2); r+=1

    def browse_local(self):
        d = filedialog.askdirectory(initialdir=str(DATA_DIR))
        if d:
            self.j_local.set(d)

    def refresh_jobs_list(self):
        self.lst_jobs.delete(0, "end")
        self.lst_dash_jobs.delete(0, "end")
        for j in self.jobs:
            flag = "ON" if j.enabled else "OFF"
            line = f"[{flag}] {j.name} | {j.mode} | {','.join(j.days)} {j.hour:02d}:{j.minute:02d} | {j.profile}"
            self.lst_jobs.insert("end", line)
            self.lst_dash_jobs.insert("end", line)

    def on_job_select(self):
        idx = self._sel_index(self.lst_jobs)
        if idx is None:
            return
        j = self.jobs[idx]
        self.j_name.set(j.name); self.j_enabled.set(j.enabled)
        self.j_profile.set(j.profile); self.j_mode.set(j.mode)
        self.j_remote.set(j.remote_source); self.j_local.set(j.local_target)
        self.j_hour.set(str(j.hour)); self.j_min.set(str(j.minute))
        self.j_subdirs.set(j.include_subdirs); self.j_keep.set(str(j.keep_last))
        self.j_dry.set(j.dry_run)
        for d in DAYS:
            self.day_vars[d].set(d in j.days)

    def job_new(self):
        prof = self.profiles[0].name if self.profiles else ""
        j = BackupJob(
            name=f"BackupJob_{len(self.jobs)+1}",
            enabled=True,
            profile=prof,
            mode="snapshot",
            remote_source="/",
            local_target=str(DATA_DIR),
            days=["Sat"],
            hour=0,
            minute=0,
            include_subdirs=True,
            keep_last=10,
            dry_run=False,
        )
        self.jobs.append(j)
        save_jobs(self.jobs)
        self.refresh_jobs_list()
        self.refresh_profiles_combo()

    def job_delete(self):
        idx = self._sel_index(self.lst_jobs)
        if idx is None:
            messagebox.showwarning("No job", "Select a job.")
            return
        j = self.jobs[idx]
        if not messagebox.askyesno("Delete", f"Delete job '{j.name}'?"):
            return
        del self.jobs[idx]
        save_jobs(self.jobs)
        self.refresh_jobs_list()

    def job_save(self):
        idx = self._sel_index(self.lst_jobs)
        if idx is None:
            messagebox.showwarning("No job", "Select a job.")
            return
        try:
            hh = int((self.j_hour.get() or "0").strip())
            mm = int((self.j_min.get() or "0").strip())
            if not (0 <= hh <= 23 and 0 <= mm <= 59):
                raise ValueError()
        except Exception:
            messagebox.showerror("Invalid time", "Hour must be 0-23 and Minute must be 0-59.")
            return
        try:
            keep = int((self.j_keep.get() or "10").strip())
            if keep < 0:
                raise ValueError()
        except Exception:
            messagebox.showerror("Invalid keep", "Keep last snapshots must be 0 or a positive number.")
            return

        days = [d for d in DAYS if self.day_vars[d].get()]
        if not days:
            messagebox.showerror("Invalid days", "Select at least one day.")
            return

        self.jobs[idx] = BackupJob(
            name=(self.j_name.get().strip() or "Unnamed Job"),
            enabled=bool(self.j_enabled.get()),
            profile=(self.j_profile.get().strip()),
            mode=(self.j_mode.get().strip() or "snapshot"),
            remote_source=(self.j_remote.get().strip() or "/"),
            local_target=(self.j_local.get().strip() or str(DATA_DIR)),
            days=days,
            hour=hh,
            minute=mm,
            include_subdirs=bool(self.j_subdirs.get()),
            keep_last=keep,
            dry_run=bool(self.j_dry.get()),
        )
        save_jobs(self.jobs)
        self.refresh_jobs_list()
        messagebox.showinfo("Saved", "Job saved.")

    # Profiles UI
    def _build_profiles(self):
        f = self.tab_profiles
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Profiles")
        left.pack(side="left", fill="both", expand=False)

        self.lst_profiles = tk.Listbox(left, width=28, height=18, exportselection=False)
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
        self.v_root = tk.StringVar(value="/")

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
        self.cmb_test_profile["values"] = names
        self.cmb_job_profile["values"] = names
        if self.active_profile and self.active_profile in names:
            self.cmb_test_profile.set(self.active_profile)
        elif names:
            self.cmb_test_profile.set(names[0])
        if names and (self.j_profile.get() not in names):
            self.j_profile.set(names[0])

    def refresh_profiles_list(self):
        self.lst_profiles.delete(0, "end")
        for p in self.profiles:
            suffix = " (active)" if self.active_profile == p.name else ""
            self.lst_profiles.insert("end", p.name + suffix)

    def on_profile_select(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None:
            return
        p = self.profiles[idx]
        self.v_name.set(p.name); self.v_host.set(p.host); self.v_port.set(str(p.port))
        self.v_user.set(p.username); self.v_pass.set(p.password); self.v_tls.set(p.tls); self.v_root.set(p.root)

    def profile_new(self):
        n = "Profile_" + str(len(self.profiles) + 1)
        self.profiles.append(Profile(n, "", 21, "", "", False, "/"))
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
            return
        p = self.profiles[idx]
        if not messagebox.askyesno("Delete", f"Delete profile '{p.name}'?"):
            return
        del self.profiles[idx]
        if self.active_profile == p.name:
            self.active_profile = self.profiles[0].name if self.profiles else None
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list(); self.refresh_profiles_combo()

    def profile_set_active(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None:
            return
        self.active_profile = self.profiles[idx].name
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list(); self.refresh_profiles_combo()

    def profile_save(self):
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

        i = self._sel_index(self.lst_profiles)
        existing_names = [p.name for p in self.profiles]

        if i is None:
            if new_profile.name in existing_names:
                messagebox.showerror("Duplicate name", "A profile with this name already exists. Pick a different name.")
                return
            self.profiles.append(new_profile)
            self.active_profile = new_profile.name
        else:
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
        messagebox.showinfo("Saved", "Profile saved.")

    # Settings UI
    def _build_settings(self):
        f = self.tab_settings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)
        box = ttk.LabelFrame(outer, text="Application Settings")
        box.pack(fill="x", expand=False, padx=6, pady=6)

        self.s_timeout = tk.StringVar(value=str(self.timeout))
        self.s_tick = tk.StringVar(value=str(self.tick_seconds))
        self.s_auto = tk.BooleanVar(value=self.auto_start)

        r=0
        ttk.Label(box, text="FTP timeout (seconds)").grid(row=r, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(box, textvariable=self.s_timeout, width=8).grid(row=r, column=1, sticky="w", pady=6); r+=1

        ttk.Label(box, text="Scheduler tick interval (seconds)").grid(row=r, column=0, sticky="w", padx=8, pady=6)
        ttk.Entry(box, textvariable=self.s_tick, width=8).grid(row=r, column=1, sticky="w", pady=6); r+=1

        ttk.Checkbutton(box, text="Auto-start scheduler on launch", variable=self.s_auto).grid(row=r, column=0, sticky="w", padx=8, pady=6); r+=1

        ttk.Button(outer, text="Save Settings", command=self.save_settings_ui, style="Colored.TButton").pack(anchor="w", padx=12, pady=10)

    def save_settings_ui(self):
        try:
            t = int((self.s_timeout.get() or "30").strip())
            k = int((self.s_tick.get() or "20").strip())
            if t <= 0 or k <= 0:
                raise ValueError()
        except Exception:
            messagebox.showerror("Invalid", "Timeout and tick must be positive numbers.")
            return
        self.timeout = t
        self.tick_seconds = k
        self.auto_start = bool(self.s_auto.get())
        self.settings = {"app":{"timeout_seconds": self.timeout, "tick_seconds": self.tick_seconds, "auto_start": self.auto_start}}
        save_json(SETTINGS_PATH, self.settings)
        messagebox.showinfo("Saved", "Settings saved.")

    # Help UI
    def _build_help(self):
        t = tk.Text(self.tab_help, wrap="word")
        t.pack(fill="both", expand=True, padx=12, pady=12)
        style_text_widget(t)
        t.insert("1.0",
            "AutomationZ Server Backup Scheduler\n\n"
            "Automated FTP/FTPS backup tool (remote -> local).\n\n"
            "Modes:\n"
            "  - Snapshot: creates timestamped folders (restore points)\n"
            "  - Mirror: keeps a persistent MIRROR folder (latest state)\n\n"
            "Profiles = your servers\n"
            "Backup Jobs = what to download + where + schedule\n\n"
            "Created by Danny van den Brande\n\n"
            "AutomationZ Server Backup Scheduler is free and open-source software.\n\n"
            "If this tool helps you automate server tasks, save time,\n"
            "or manage multiple servers more easily,\n"
            "consider supporting development with a donation.\n\n"
            "Donations are optional, but appreciated and help\n"
            "support ongoing development and improvements.\n\n"
            "Support link:\n"
            "https://ko-fi.com/dannyvandenbrande\n"
        )
        t.configure(state="disabled")

    def refresh_jobs_list(self):
        # called before dashboard build? safeguard
        if hasattr(self, "lst_jobs") and hasattr(self, "lst_dash_jobs"):
            self.lst_jobs.delete(0, "end")
            self.lst_dash_jobs.delete(0, "end")
            for j in self.jobs:
                flag = "ON" if j.enabled else "OFF"
                line = f"[{flag}] {j.name} | {j.mode} | {','.join(j.days)} {j.hour:02d}:{j.minute:02d} | {j.profile}"
                self.lst_jobs.insert("end", line)
                self.lst_dash_jobs.insert("end", line)

    def _sel_index(self, lb: tk.Listbox) -> Optional[int]:
        sel = lb.curselection()
        return int(sel[0]) if sel else None

def main():
    for p in (CONFIG_DIR, DATA_DIR):
        p.mkdir(parents=True, exist_ok=True)
    App().mainloop()

if __name__ == "__main__":
    main()
