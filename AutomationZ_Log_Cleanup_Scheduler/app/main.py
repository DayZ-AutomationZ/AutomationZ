#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import time
import pathlib
import datetime
import traceback
import fnmatch
from dataclasses import dataclass
from typing import List, Dict, Any, Optional, Tuple

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

import ftplib

APP_NAME = "AutomationZ Log Cleanup Scheduler"
APP_VERSION = "1.0.0"

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"

CONFIG_PATH = CONFIG_DIR / "log_cleanup_config.json"



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

# ------------------------- helpers -------------------------

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def weekday_name(i: int) -> str:
    return ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][i % 7]

def parse_csv(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]

def norm_remote(path: str) -> str:
    return (path or "").replace("\\", "/")

def open_path(path: pathlib.Path) -> None:
    try:
        p = str(path)
        if sys.platform.startswith("win"):
            os.startfile(p)  # type: ignore
        elif sys.platform == "darwin":
            os.system(f'open "{p}"')
        else:
            os.system(f'xdg-open "{p}"')
    except Exception as e:
        raise RuntimeError(str(e))

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

def matches_any(name: str, patterns: List[str]) -> bool:
    name = name or ""
    for pat in patterns:
        pat = (pat or "").strip()
        if not pat:
            continue
        if fnmatch.fnmatch(name, pat):
            return True
    return False

# ------------------------- logging -------------------------

class Logger:
    def __init__(self, widget: tk.Text):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.widget = widget
        self.file = LOGS_DIR / ("cleanup_" + now_stamp() + ".log")
        self._write(f"{APP_NAME} v{APP_VERSION}\n\n")

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

# ------------------------- models -------------------------

@dataclass
class FTPTarget:
    name: str
    host: str
    port: int
    username: str
    password: str
    tls: bool

@dataclass
class Job:
    name: str
    enabled: bool
    mode: str  # local|ftp
    # local
    local_folders: List[str]
    # ftp
    ftp_target: str
    ftp_folders: List[str]  # remote folders
    # exclusions
    exclude_files: List[str]
    exclude_folders: List[str]
    # schedule
    schedule_enabled: bool
    days: List[int]
    hour: int
    minute: int
    last_run_key: str
    # safety
    dry_run: bool

# ------------------------- FTP client -------------------------

class FTPClient:
    def __init__(self, t: FTPTarget, timeout: int = 25):
        self.t = t
        self.timeout = timeout
        self.ftp = None

    def connect(self):
        ftp = ftplib.FTP_TLS(timeout=self.timeout) if self.t.tls else ftplib.FTP(timeout=self.timeout)
        ftp.connect(self.t.host, int(self.t.port))
        ftp.login(self.t.username, self.t.password)
        if self.t.tls and isinstance(ftp, ftplib.FTP_TLS):
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

    def list_dir(self, remote_dir: str) -> List[Tuple[str, bool]]:
        """
        Returns list of (name, is_dir) in remote_dir.
        Uses MLSD when available, falls back to NLST + cwd test.
        """
        assert self.ftp is not None
        remote_dir = remote_dir.rstrip("/") or "/"
        items: List[Tuple[str, bool]] = []

        # Try MLSD
        try:
            self.ftp.cwd(remote_dir)
            for name, facts in self.ftp.mlsd():
                if name in (".", ".."):
                    continue
                typ = (facts.get("type") or "").lower()
                is_dir = typ == "dir"
                items.append((name, is_dir))
            return items
        except Exception:
            pass

        # Fallback: NLST + try cwd
        self.ftp.cwd(remote_dir)
        try:
            names = self.ftp.nlst()
        except Exception:
            names = []
        # nlst may return full paths; normalize to base names
        for n in names:
            bn = n.rstrip("/").split("/")[-1]
            if bn in (".", "..", ""):
                continue
            # test dir by trying cwd
            is_dir = False
            cur = self.ftp.pwd()
            try:
                self.ftp.cwd(remote_dir + "/" + bn)
                is_dir = True
            except Exception:
                is_dir = False
            finally:
                try:
                    self.ftp.cwd(cur)
                except Exception:
                    self.ftp.cwd(remote_dir)
            items.append((bn, is_dir))
        return items

    def delete_file(self, remote_path: str):
        assert self.ftp is not None
        self.ftp.delete(remote_path)

    def remove_dir(self, remote_path: str):
        assert self.ftp is not None
        self.ftp.rmd(remote_path)

# ------------------------- core cleanup -------------------------

def local_cleanup_folder(folder: pathlib.Path, exclude_files: List[str], exclude_folders: List[str], dry_run: bool, log: Logger) -> Tuple[int,int]:
    deleted_files = 0
    deleted_dirs = 0

    if not folder.exists():
        log.warn(f"Local folder missing: {folder}")
        return (0,0)
    if not folder.is_dir():
        log.warn(f"Not a directory: {folder}")
        return (0,0)

    # walk bottom-up so we can remove empty dirs
    for root, dirs, files in os.walk(folder, topdown=False):
        rootp = pathlib.Path(root)

        # files
        for fn in files:
            if matches_any(fn, exclude_files):
                continue
            fp = rootp / fn
            try:
                if dry_run:
                    log.info(f"[DRY] delete file: {fp}")
                else:
                    fp.unlink(missing_ok=True)
                    log.info(f"Deleted file: {fp}")
                deleted_files += 1
            except Exception as e:
                log.warn(f"Failed delete file: {fp} :: {e}")

        # dirs (optional cleanup of empty dirs; but we NEVER delete excluded folders)
        for dn in dirs:
            if matches_any(dn, exclude_folders):
                continue
            dp = rootp / dn
            try:
                # delete only if empty
                if dp.exists() and dp.is_dir() and not any(dp.iterdir()):
                    if dry_run:
                        log.info(f"[DRY] remove empty dir: {dp}")
                    else:
                        dp.rmdir()
                        log.info(f"Removed empty dir: {dp}")
                    deleted_dirs += 1
            except Exception:
                pass

    return (deleted_files, deleted_dirs)

def ftp_cleanup_folder(cli: FTPClient, remote_folder: str, exclude_files: List[str], exclude_folders: List[str], dry_run: bool, log: Logger) -> Tuple[int,int]:
    """
    Deletes files inside remote_folder (and subfolders), excluding patterns.
    Removes empty dirs (not excluded).
    """
    deleted_files = 0
    deleted_dirs = 0

    remote_folder = norm_remote(remote_folder).rstrip("/")
    if not remote_folder.startswith("/"):
        remote_folder = "/" + remote_folder

    def walk_dir(rdir: str):
        nonlocal deleted_files, deleted_dirs
        try:
            items = cli.list_dir(rdir)
        except Exception as e:
            log.warn(f"FTP list failed: {rdir} :: {e}")
            return

        # first recurse into directories
        for name, is_dir in items:
            if is_dir:
                if matches_any(name, exclude_folders):
                    continue
                walk_dir(rdir.rstrip("/") + "/" + name)

        # then delete files
        for name, is_dir in items:
            if is_dir:
                continue
            if matches_any(name, exclude_files):
                continue
            p = rdir.rstrip("/") + "/" + name
            try:
                if dry_run:
                    log.info(f"[DRY] delete remote file: {p}")
                else:
                    cli.delete_file(p)
                    log.info(f"Deleted remote file: {p}")
                deleted_files += 1
            except Exception as e:
                log.warn(f"Failed delete remote file: {p} :: {e}")

        # finally remove dir if empty (and not root of job)
        if rdir != remote_folder:
            try:
                # re-list to check emptiness
                items2 = cli.list_dir(rdir)
                if not items2:
                    if dry_run:
                        log.info(f"[DRY] remove remote empty dir: {rdir}")
                    else:
                        cli.remove_dir(rdir)
                        log.info(f"Removed remote empty dir: {rdir}")
                    deleted_dirs += 1
            except Exception:
                pass

    walk_dir(remote_folder)
    return (deleted_files, deleted_dirs)

# ------------------------- persistence -------------------------

def default_config() -> Dict[str, Any]:
    return {
        "app": {"tick_seconds": 15, "timeout_seconds": 25},
        "ftp_targets": [
            {
                "name": "MyServerFTP",
                "host": "FTP.HOST.COM",
                "port": 21,
                "username": "username",
                "password": "password",
                "tls": False
            }
        ],
        "jobs": [
            {
                "name": "Local Logs (example)",
                "enabled": True,
                "mode": "local",
                "local_folders": [
                    "C:/path/to/logs",
                    "C:/path/to/other/logs"
                ],
                "ftp_target": "MyServerFTP",
                "ftp_folders": [
                    "/dayzstandalone/logs"
                ],
                "exclude_files": ["*.json", "*.cfg", "keep_me.txt"],
                "exclude_folders": ["config", "settings"],
                "schedule_enabled": False,
                "days": [0,1,2,3,4,5,6],
                "hour": 3,
                "minute": 0,
                "last_run_key": "",
                "dry_run": True
            }
        ]
    }

def load_state() -> Tuple[Dict[str, Any], List[FTPTarget], List[Job]]:
    obj = load_json(CONFIG_PATH, default_config())

    # normalize app defaults
    obj.setdefault("app", {})
    obj["app"].setdefault("tick_seconds", 15)
    obj["app"].setdefault("timeout_seconds", 25)
    obj.setdefault("ftp_targets", [])
    obj.setdefault("jobs", [])

    targets: List[FTPTarget] = []
    for t in obj.get("ftp_targets", []):
        targets.append(FTPTarget(
            name=t.get("name","Target"),
            host=t.get("host",""),
            port=int(t.get("port",21)),
            username=t.get("username",""),
            password=t.get("password",""),
            tls=bool(t.get("tls", False)),
        ))

    jobs: List[Job] = []
    for j in obj.get("jobs", []):
        jobs.append(Job(
            name=j.get("name","Job"),
            enabled=bool(j.get("enabled", True)),
            mode=j.get("mode","local"),
            local_folders=list(j.get("local_folders", [])),
            ftp_target=j.get("ftp_target",""),
            ftp_folders=list(j.get("ftp_folders", [])),
            exclude_files=list(j.get("exclude_files", [])),
            exclude_folders=list(j.get("exclude_folders", [])),
            schedule_enabled=bool(j.get("schedule_enabled", False)),
            days=list(j.get("days", [0,1,2,3,4,5,6])),
            hour=int(j.get("hour", 0)),
            minute=int(j.get("minute", 0)),
            last_run_key=j.get("last_run_key",""),
            dry_run=bool(j.get("dry_run", True)),
        ))

    save_json(CONFIG_PATH, obj)
    return obj, targets, jobs

def save_state(obj: Dict[str, Any], targets: List[FTPTarget], jobs: List[Job]) -> None:
    obj["ftp_targets"] = [t.__dict__ for t in targets]
    obj["jobs"] = [j.__dict__ for j in jobs]
    save_json(CONFIG_PATH, obj)

# ------------------------- UI -------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.style = apply_dark_theme(self)
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1120x760")
        self.minsize(980, 640)

        self.obj, self.ftp_targets, self.jobs = load_state()

        self.tick_seconds = int((self.obj.get("app", {}) or {}).get("tick_seconds", 15))
        self.timeout_seconds = int((self.obj.get("app", {}) or {}).get("timeout_seconds", 25))

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_dashboard = ttk.Frame(nb)
        self.tab_jobs = ttk.Frame(nb)
        self.tab_ftp = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        self.tab_help = ttk.Frame(nb)

        nb.add(self.tab_dashboard, text="Dashboard")
        nb.add(self.tab_jobs, text="Jobs")
        nb.add(self.tab_ftp, text="FTP Targets")
        nb.add(self.tab_settings, text="Settings")
        nb.add(self.tab_help, text="Help")

        log_box = ttk.LabelFrame(self, text="Log")
        log_box.pack(fill="both", expand=False, padx=10, pady=8)
        self.log_text = tk.Text(log_box, height=10, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        style_text_widget(self.log_text)
        self.log = Logger(self.log_text)

        self._running = False

        self._build_dashboard()
        self._build_jobs()
        self._build_ftp()
        self._build_settings()
        self._build_help()

        self.refresh_all()
        self.after(1000, self._tick)

    def refresh_all(self):
        self.refresh_jobs_list()
        self.refresh_ftp_list()
        self.refresh_dashboard()

    # ---------------- Dashboard ----------------

    def _build_dashboard(self):
        f = self.tab_dashboard
        top = ttk.Frame(f); top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Job:").grid(row=0, column=0, sticky="w")
        self.cmb_job = ttk.Combobox(top, state="readonly", width=45)
        self.cmb_job.grid(row=0, column=1, sticky="w", padx=(6,18))

        ttk.Button(top, text="Run Job Now", command=self.run_selected_job, style="Colored.TButton").grid(row=0, column=2, sticky="w", padx=(0,10))
        self.btn_start = ttk.Button(top, text="Start Scheduler", command=self.toggle_scheduler, style="Colored.TButton")
        self.btn_start.grid(row=0, column=3, sticky="w")

        status = ttk.LabelFrame(f, text="Next / Status")
        status.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.txt_status = tk.Text(status, height=18, wrap="word", state="disabled")
        self.txt_status.pack(fill="both", expand=True, padx=8, pady=8)
        style_text_widget(self.txt_status)

        quick = ttk.Frame(f); quick.pack(fill="x", padx=12, pady=(0,10))
        ttk.Button(quick, text="Open Config Folder", command=lambda: self._open_safe(CONFIG_DIR), style="Colored.TButton").pack(side="left")
        ttk.Button(quick, text="Open Logs Folder", command=lambda: self._open_safe(LOGS_DIR), style="Colored.TButton").pack(side="left", padx=8)
        ttk.Button(quick, text="Open Config File", command=lambda: self._open_safe(CONFIG_PATH), style="Colored.TButton").pack(side="left", padx=8)

    def _open_safe(self, path: pathlib.Path) -> None:
        try:
            open_path(path)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def toggle_scheduler(self):
        self._running = not self._running
        self.btn_start.configure(text=("Stop Scheduler" if self._running else "Start Scheduler"))
        self.log.info("Scheduler " + ("started." if self._running else "stopped."))
        self.refresh_dashboard()

    def refresh_dashboard(self):
        lines = []
        now = datetime.datetime.now()
        lines.append(f"Config file: {CONFIG_PATH}")
        lines.append(f"Scheduler: {'RUNNING' if self._running else 'STOPPED'}")
        lines.append(f"Now: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        due_list = []
        for j in self.jobs:
            if not j.enabled or not j.schedule_enabled:
                continue
            days = ",".join(weekday_name(d) for d in j.days) if j.days else "None"
            due_list.append(f"- {j.name} @ {j.hour:02d}:{j.minute:02d} [{days}] mode={j.mode} dry_run={j.dry_run}")

        lines.append("Scheduled jobs:")
        lines.extend(due_list or ["- (none)"])

        self.txt_status.configure(state="normal")
        self.txt_status.delete("1.0", "end")
        self.txt_status.insert("1.0", "\n".join(lines))
        self.txt_status.configure(state="disabled")

    def run_selected_job(self):
        name = (self.cmb_job.get() or "").strip()
        job = next((j for j in self.jobs if j.name == name), None)
        if not job:
            messagebox.showwarning("No job", "Select a job first.")
            return
        if not messagebox.askyesno("Confirm", f"Run job '{job.name}' now?"):
            return
        try:
            self.run_job(job)
        except Exception as e:
            self.log.error(str(e))
            self.log.error(traceback.format_exc())

    def _tick(self):
        try:
            self.refresh_dashboard()
            if self._running:
                self._run_due_jobs()
        except Exception as e:
            self.log.error("Scheduler tick error: " + str(e))
        finally:
            self.after(max(5, int(self.tick_seconds)) * 1000, self._tick)

    def _run_due_jobs(self):
        now = datetime.datetime.now()
        key = now.strftime("%Y%m%d_%H%M")
        dow = now.weekday()
        changed = False

        for j in self.jobs:
            if not j.enabled or not j.schedule_enabled:
                continue
            if dow not in j.days:
                continue
            if now.hour != int(j.hour) or now.minute != int(j.minute):
                continue
            if j.last_run_key == key:
                continue

            self.log.info(f"Due job: {j.name} at {key}")
            try:
                self.run_job(j)
            finally:
                j.last_run_key = key
                changed = True

        if changed:
            save_state(self.obj, self.ftp_targets, self.jobs)

    # ---------------- core run ----------------

    def run_job(self, job: Job) -> None:
        self.log.info(f"Job start: {job.name} (mode={job.mode}, dry_run={job.dry_run})")

        if job.mode == "local":
            total_f = total_d = 0
            for p in job.local_folders:
                folder = pathlib.Path(p).expanduser()
                fcnt, dcnt = local_cleanup_folder(folder, job.exclude_files, job.exclude_folders, job.dry_run, self.log)
                total_f += fcnt; total_d += dcnt
            self.log.info(f"Job done: {job.name} (deleted_files={total_f}, removed_dirs={total_d})")
            return

        if job.mode == "ftp":
            t = next((x for x in self.ftp_targets if x.name == job.ftp_target), None)
            if not t:
                raise RuntimeError(f"FTP target not found: {job.ftp_target}")

            cli = FTPClient(t, timeout=self.timeout_seconds)
            cli.connect()
            try:
                total_f = total_d = 0
                for rf in job.ftp_folders:
                    fcnt, dcnt = ftp_cleanup_folder(cli, rf, job.exclude_files, job.exclude_folders, job.dry_run, self.log)
                    total_f += fcnt; total_d += dcnt
                self.log.info(f"Job done: {job.name} (deleted_files={total_f}, removed_dirs={total_d})")
            finally:
                cli.close()
            return

        raise RuntimeError(f"Unknown mode: {job.mode}")

    # ---------------- Jobs tab ----------------

    def _build_jobs(self):
        f = self.tab_jobs
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Jobs")
        left.pack(side="left", fill="both", expand=False)

        self.lst_jobs = tk.Listbox(left, width=42, height=18, exportselection=False)
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

        self._jobs_selected: Optional[int] = None

        self.vj_name = tk.StringVar()
        self.vj_enabled = tk.BooleanVar(value=True)
        self.vj_mode = tk.StringVar(value="local")

        self.vj_local_folders = tk.StringVar()

        self.vj_ftp_target = tk.StringVar()
        self.vj_ftp_folders = tk.StringVar()

        self.vj_ex_files = tk.StringVar(value="*.json,*.cfg")
        self.vj_ex_folders = tk.StringVar(value="config,settings")
        self.vj_dry = tk.BooleanVar(value=True)

        self.vj_sched_enabled = tk.BooleanVar(value=False)
        self.vj_hour = tk.StringVar(value="3")
        self.vj_min = tk.StringVar(value="0")
        self.vj_days = {i: tk.BooleanVar(value=True) for i in range(7)}

        def bind_keep(widget):
            widget.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_jobs, self._jobs_selected))
            return widget

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vj_name, width=60)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        bind_keep(ttk.Checkbutton(form, text="Enabled", variable=self.vj_enabled)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Mode").grid(row=r, column=0, sticky="w", pady=2)
        cmb = ttk.Combobox(form, textvariable=self.vj_mode, state="readonly", width=10, values=["local","ftp"])
        cmb.grid(row=r, column=1, sticky="w", pady=2)
        bind_keep(cmb); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        ttk.Label(form, text="Local folders (one per line)").grid(row=r, column=0, sticky="nw", pady=2)
        self.txt_local = tk.Text(form, height=6, width=70)
        self.txt_local.grid(row=r, column=1, sticky="w", pady=2)
        style_text_widget(self.txt_local)
        bind_keep(self.txt_local)
        r+=1
        ttk.Button(form, text="Add local folder…", command=self.add_local_folder, style="Colored.TButton").grid(row=r, column=1, sticky="w", pady=(0,8))
        r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        ttk.Label(form, text="FTP target (mode=ftp)").grid(row=r, column=0, sticky="w", pady=2)
        self.cmb_job_ftp = ttk.Combobox(form, textvariable=self.vj_ftp_target, state="readonly", width=25)
        self.cmb_job_ftp.grid(row=r, column=1, sticky="w", pady=2)
        bind_keep(self.cmb_job_ftp); r+=1

        ttk.Label(form, text="FTP folders (one per line) (mode=ftp)").grid(row=r, column=0, sticky="nw", pady=2)
        self.txt_ftp = tk.Text(form, height=6, width=70)
        self.txt_ftp.grid(row=r, column=1, sticky="w", pady=2)
        style_text_widget(self.txt_ftp)
        bind_keep(self.txt_ftp); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        ttk.Label(form, text="Exclude file patterns (comma-separated)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vj_ex_files, width=60)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Exclude folder names (comma-separated)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vj_ex_folders, width=60)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        bind_keep(ttk.Checkbutton(form, text="Dry run (log only, no deletion)", variable=self.vj_dry)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        bind_keep(ttk.Checkbutton(form, text="Enable schedule (run automatically)", variable=self.vj_sched_enabled)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        hhmm = ttk.Frame(form); hhmm.grid(row=r, column=1, sticky="w", pady=2)
        ttk.Label(hhmm, text="Time:").pack(side="left")
        bind_keep(ttk.Entry(hhmm, textvariable=self.vj_hour, width=4)).pack(side="left", padx=(6,2))
        ttk.Label(hhmm, text=":").pack(side="left")
        bind_keep(ttk.Entry(hhmm, textvariable=self.vj_min, width=4)).pack(side="left", padx=(2,10))
        ttk.Label(hhmm, text="(24h)").pack(side="left")
        r+=1

        daysf = ttk.Frame(form); daysf.grid(row=r, column=1, sticky="w", pady=(4,2))
        ttk.Label(form, text="Days:").grid(row=r, column=0, sticky="w", pady=(4,2))
        for i in range(7):
            bind_keep(ttk.Checkbutton(daysf, text=weekday_name(i), variable=self.vj_days[i])).pack(side="left", padx=3)
        r+=1

        ttk.Button(form, text="Tip: Edit config JSON directly", command=lambda: self._open_safe(CONFIG_PATH), style="Colored.TButton").grid(row=r, column=1, sticky="w", pady=(10,2))

    def add_local_folder(self):
        p = filedialog.askdirectory(title="Select a local folder to clean")
        if not p:
            return
        cur = (self.txt_local.get("1.0", "end") or "").strip()
        new = (cur + "\n" + p).strip() if cur else p
        self.txt_local.delete("1.0", "end")
        self.txt_local.insert("1.0", new)

    def refresh_jobs_list(self):
        self.lst_jobs.delete(0, "end")
        for j in self.jobs:
            flag = "ON" if j.enabled else "OFF"
            sch = "AUTO" if (j.schedule_enabled and j.enabled) else "MANUAL"
            self.lst_jobs.insert("end", f"[{flag}/{sch}] {j.name} ({j.mode})")
        self.cmb_job["values"] = [j.name for j in self.jobs]
        if self.jobs and (self.cmb_job.get() not in [j.name for j in self.jobs]):
            self.cmb_job.set(self.jobs[0].name)

        self.cmb_job_ftp["values"] = [t.name for t in self.ftp_targets]
        if self.ftp_targets and (self.vj_ftp_target.get() not in [t.name for t in self.ftp_targets]):
            self.vj_ftp_target.set(self.ftp_targets[0].name)

    def _sel_index(self, lb: tk.Listbox) -> Optional[int]:
        sel = lb.curselection()
        return int(sel[0]) if sel else None

    def _restore_sel(self, lb: tk.Listbox, idx: Optional[int]) -> None:
        if idx is None:
            return
        try:
            lb.selection_clear(0, "end")
            lb.selection_set(idx)
            lb.see(idx)
        except Exception:
            pass

    def on_job_select(self):
        idx = self._sel_index(self.lst_jobs)
        self._jobs_selected = idx
        if idx is None:
            return
        j = self.jobs[idx]
        self.vj_name.set(j.name)
        self.vj_enabled.set(j.enabled)
        self.vj_mode.set(j.mode)

        self.txt_local.delete("1.0", "end")
        self.txt_local.insert("1.0", "\n".join(j.local_folders))

        self.vj_ftp_target.set(j.ftp_target)
        self.txt_ftp.delete("1.0", "end")
        self.txt_ftp.insert("1.0", "\n".join(j.ftp_folders))

        self.vj_ex_files.set(",".join(j.exclude_files))
        self.vj_ex_folders.set(",".join(j.exclude_folders))
        self.vj_dry.set(j.dry_run)

        self.vj_sched_enabled.set(j.schedule_enabled)
        self.vj_hour.set(str(j.hour))
        self.vj_min.set(str(j.minute))
        for i in range(7):
            self.vj_days[i].set(i in j.days)

    def job_new(self):
        default_target = self.ftp_targets[0].name if self.ftp_targets else ""
        self.jobs.append(Job(
            name=f"Job_{len(self.jobs)+1}",
            enabled=True,
            mode="local",
            local_folders=[],
            ftp_target=default_target,
            ftp_folders=[],
            exclude_files=["*.json","*.cfg"],
            exclude_folders=["config","settings"],
            schedule_enabled=False,
            days=[0,1,2,3,4,5,6],
            hour=3,
            minute=0,
            last_run_key="",
            dry_run=True,
        ))
        save_state(self.obj, self.ftp_targets, self.jobs)
        self.refresh_jobs_list()

    def job_delete(self):
        idx = self._sel_index(self.lst_jobs)
        if idx is None:
            return
        j = self.jobs[idx]
        if not messagebox.askyesno("Delete", f"Delete job '{j.name}'?"):
            return
        del self.jobs[idx]
        save_state(self.obj, self.ftp_targets, self.jobs)
        self.refresh_jobs_list()

    def job_save(self):
        idx = self._sel_index(self.lst_jobs)
        if idx is None:
            messagebox.showwarning("No job", "Select a job first.")
            return
        try:
            hh = int((self.vj_hour.get() or "0").strip())
            mm = int((self.vj_min.get() or "0").strip())
            if hh < 0 or hh > 23 or mm < 0 or mm > 59:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Invalid", "Hour must be 0-23 and minute 0-59.")
            return

        days = [i for i in range(7) if bool(self.vj_days[i].get())] or [0,1,2,3,4,5,6]

        local_folders = [ln.strip() for ln in (self.txt_local.get("1.0","end") or "").splitlines() if ln.strip()]
        ftp_folders = [ln.strip() for ln in (self.txt_ftp.get("1.0","end") or "").splitlines() if ln.strip()]

        self.jobs[idx] = Job(
            name=(self.vj_name.get().strip() or self.jobs[idx].name),
            enabled=bool(self.vj_enabled.get()),
            mode=(self.vj_mode.get().strip() or "local"),
            local_folders=local_folders,
            ftp_target=(self.vj_ftp_target.get().strip()),
            ftp_folders=ftp_folders,
            exclude_files=parse_csv(self.vj_ex_files.get()),
            exclude_folders=parse_csv(self.vj_ex_folders.get()),
            schedule_enabled=bool(self.vj_sched_enabled.get()),
            days=days,
            hour=hh,
            minute=mm,
            last_run_key=self.jobs[idx].last_run_key,
            dry_run=bool(self.vj_dry.get()),
        )

        save_state(self.obj, self.ftp_targets, self.jobs)
        self.refresh_jobs_list()
        self.refresh_dashboard()
        messagebox.showinfo("Saved", "Job saved.")

    # ---------------- FTP Targets tab ----------------

    def _build_ftp(self):
        f = self.tab_ftp
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="FTP Targets")
        left.pack(side="left", fill="both", expand=False)

        self.lst_ftp = tk.Listbox(left, width=42, height=18, exportselection=False)
        self.lst_ftp.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_ftp)
        self.lst_ftp.bind("<<ListboxSelect>>", lambda e: self.on_ftp_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.ftp_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.ftp_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.ftp_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="FTP details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self._ftp_selected: Optional[int] = None

        self.vt_name = tk.StringVar()
        self.vt_host = tk.StringVar()
        self.vt_port = tk.StringVar(value="21")
        self.vt_user = tk.StringVar()
        self.vt_pass = tk.StringVar()
        self.vt_tls  = tk.BooleanVar(value=False)

        def bind_keep(widget):
            widget.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_ftp, self._ftp_selected))
            return widget

        def entry(row, label, var, width=54, show=None):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=2)
            e = ttk.Entry(form, textvariable=var, width=width, show=show)
            e.grid(row=row, column=1, sticky="w", pady=2)
            bind_keep(e)
            return e

        r=0
        entry(r, "Name", self.vt_name); r+=1
        entry(r, "Host", self.vt_host); r+=1
        entry(r, "Port", self.vt_port, width=10); r+=1
        entry(r, "Username", self.vt_user); r+=1
        entry(r, "Password", self.vt_pass, show="*"); r+=1
        bind_keep(ttk.Checkbutton(form, text="Use FTPS (TLS)", variable=self.vt_tls)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=10); r+=1
        ttk.Button(form, text="Test connect", command=self.ftp_test, style="Colored.TButton").grid(row=r, column=1, sticky="w")

    def refresh_ftp_list(self):
        self.lst_ftp.delete(0, "end")
        for t in self.ftp_targets:
            tag = "FTPS" if t.tls else "FTP"
            self.lst_ftp.insert("end", f"{t.name} [{tag}] {t.host}:{t.port}")

    def on_ftp_select(self):
        idx = self._sel_index(self.lst_ftp)
        self._ftp_selected = idx
        if idx is None:
            return
        t = self.ftp_targets[idx]
        self.vt_name.set(t.name)
        self.vt_host.set(t.host)
        self.vt_port.set(str(t.port))
        self.vt_user.set(t.username)
        self.vt_pass.set(t.password)
        self.vt_tls.set(t.tls)

    def ftp_new(self):
        self.ftp_targets.append(FTPTarget(
            name=f"Target_{len(self.ftp_targets)+1}",
            host="", port=21, username="", password="", tls=False
        ))
        save_state(self.obj, self.ftp_targets, self.jobs)
        self.refresh_ftp_list()
        self.refresh_jobs_list()

    def ftp_delete(self):
        idx = self._sel_index(self.lst_ftp)
        if idx is None:
            return
        t = self.ftp_targets[idx]
        if not messagebox.askyesno("Delete", f"Delete FTP target '{t.name}'?"):
            return
        del self.ftp_targets[idx]
        # if jobs reference it, keep name but user must fix
        save_state(self.obj, self.ftp_targets, self.jobs)
        self.refresh_ftp_list()
        self.refresh_jobs_list()

    def ftp_save(self):
        idx = self._sel_index(self.lst_ftp)
        if idx is None:
            messagebox.showwarning("No target", "Select an FTP target first.")
            return
        try:
            port = int((self.vt_port.get() or "21").strip())
        except ValueError:
            messagebox.showerror("Invalid", "Port must be a number.")
            return
        self.ftp_targets[idx] = FTPTarget(
            name=self.vt_name.get().strip() or self.ftp_targets[idx].name,
            host=self.vt_host.get().strip(),
            port=port,
            username=self.vt_user.get().strip(),
            password=self.vt_pass.get(),
            tls=bool(self.vt_tls.get()),
        )
        save_state(self.obj, self.ftp_targets, self.jobs)
        self.refresh_ftp_list()
        self.refresh_jobs_list()
        messagebox.showinfo("Saved", "FTP target saved.")

    def ftp_test(self):
        idx = self._sel_index(self.lst_ftp)
        if idx is None:
            messagebox.showwarning("No target", "Select an FTP target first.")
            return
        try:
            self.ftp_save()
            t = self.ftp_targets[idx]
            cli = FTPClient(t, timeout=self.timeout_seconds)
            cli.connect()
            try:
                # try PWD
                _ = cli.ftp.pwd()  # type: ignore
            finally:
                cli.close()
            messagebox.showinfo("OK", "Connected successfully.")
        except Exception as e:
            messagebox.showerror("Failed", str(e))

    # ---------------- Settings tab ----------------

    def _build_settings(self):
        f = self.tab_settings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        box = ttk.LabelFrame(outer, text="App Settings")
        box.pack(fill="x", padx=6, pady=6)

        self.vs_tick = tk.StringVar(value=str(self.tick_seconds))
        self.vs_timeout = tk.StringVar(value=str(self.timeout_seconds))

        row = ttk.Frame(box); row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="Scheduler tick seconds").pack(side="left")
        ttk.Entry(row, textvariable=self.vs_tick, width=6).pack(side="left", padx=(6,14))
        ttk.Label(row, text="FTP timeout seconds").pack(side="left")
        ttk.Entry(row, textvariable=self.vs_timeout, width=6).pack(side="left", padx=(6,14))
        ttk.Button(row, text="Save Settings", command=self.settings_save, style="Colored.TButton").pack(side="left", padx=(10,0))

        info = tk.Text(outer, height=10, wrap="word")
        info.pack(fill="both", expand=True, padx=6, pady=(10,6))
        style_text_widget(info)
        info.insert("1.0",
            "Notes:\n"
            "- Exclude patterns support wildcards, e.g. *.json, *.cfg, *.log\n"
            "- Exclude folders are matched by folder NAME (not full path), e.g. config, settings\n"
            "- Dry run logs what would be deleted; switch it off only when you're sure.\n"
            "- For complicated setups, edit config/log_cleanup_config.json directly.\n"
        )
        info.configure(state="disabled")

    def settings_save(self):
        try:
            tick = int((self.vs_tick.get() or "15").strip())
            timeout = int((self.vs_timeout.get() or "25").strip())
        except ValueError:
            messagebox.showerror("Invalid", "Numbers only.")
            return
        self.obj.setdefault("app", {})
        self.obj["app"]["tick_seconds"] = max(5, tick)
        self.obj["app"]["timeout_seconds"] = max(5, timeout)
        save_state(self.obj, self.ftp_targets, self.jobs)
        self.tick_seconds = int(self.obj["app"]["tick_seconds"])
        self.timeout_seconds = int(self.obj["app"]["timeout_seconds"])
        messagebox.showinfo("Saved", "Settings saved.")

    # ---------------- Help tab ----------------

    def _build_help(self):
        t = tk.Text(self.tab_help, wrap="word")
        t.pack(fill="both", expand=True, padx=12, pady=12)
        style_text_widget(t)
        t.insert("1.0",
            f"{APP_NAME}\n"
            "Delete Logs on a Schedule!\n\n"
            "What this does\n"
            "- Create cleanup jobs that delete files from log folders.\n"
            "- Local mode: cleans folders on your PC/RPi.\n"
            "- FTP mode: cleans folders on a remote server (FTP/FTPS).\n"
            "- Exclude patterns: keep config files etc (blacklist/whitelist behavior).\n"
            "- Scheduler: run jobs automatically on selected days/time.\n\n"
            "Safety\n"
            "- Start with DRY RUN enabled.\n"
            "- When you are sure, disable Dry run for the job.\n\n"
            "Created by Danny van den Brande\n\n"
            "AutomationZ Server Backup Scheduler is free and open-source software.\n\n"
            "If this tool helps you automate server tasks, save time,\n"
            "or manage multiple servers more easily,\n"
            "consider supporting development with a donation.\n\n"
            "Donations are optional, but appreciated and help\n"
            "support ongoing development and improvements.\n\n"
            "Support link:\n"
            "https://ko-fi.com/dannyvandenbrande\n"
            "Where config is saved\n"
            f"- {CONFIG_PATH}\n"
        )
        t.configure(state="disabled")

def main():
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    App().mainloop()

if __name__ == "__main__":
    main()
