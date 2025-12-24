#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import time
import ftplib
import pathlib
import datetime
import traceback
import threading
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

import urllib.request

APP_NAME = "AutomationZ Server Health"
APP_VERSION = "1.0.1"

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
STATE_DIR = BASE_DIR / "state"
CACHE_DIR = BASE_DIR / "logs_cache"
REPORTS_DIR = BASE_DIR / "reports"

PROFILES_PATH = CONFIG_DIR / "profiles.json"
WATCHES_PATH  = CONFIG_DIR / "watches.json"
SETTINGS_PATH = CONFIG_DIR / "settings.json"
OFFSETS_PATH  = STATE_DIR / "offsets.json"
EVENTS_PATH   = STATE_DIR / "events.json"



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
    p = (path or "").replace("\\", "/")
    p = p.replace("\r", "").replace("\n", "")
    return p.lstrip("/")

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
        (BASE_DIR / "logs").mkdir(parents=True, exist_ok=True)
        self.widget = widget
        self.file = (BASE_DIR / "logs") / ("server_health_" + now_stamp() + ".log")
        self._write(APP_NAME + " v" + APP_VERSION + "\n\n")

    def _write(self, s: str) -> None:
        with open(self.file, "a", encoding="utf-8") as f:
            f.write(s)

    def log(self, level: str, msg: str) -> None:
        line = f"[{level}] {msg}\n"
        self._write(line)
        try:
            self.widget.configure(state="normal")
            self.widget.insert("end", line)
            self.widget.see("end")
            self.widget.configure(state="disabled")
        except Exception:
            pass

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
class Watch:
    name: str
    enabled: bool
    source: str   # "ftp" or "local"
    path: str     # remote_path (relative to root) OR local absolute path
    kind: str     # "log"

def load_profiles() -> Tuple[List[Profile], Optional[str]]:
    obj = load_json(PROFILES_PATH, {"profiles": [], "active_profile": None})
    out: List[Profile] = []
    for p in obj.get("profiles", []):
        out.append(Profile(
            name=p.get("name","Unnamed"),
            host=p.get("host",""),
            port=int(p.get("port",21)),
            username=p.get("username",""),
            password=p.get("password",""),
            tls=bool(p.get("tls", False)),
            root=p.get("root","/"),
        ))
    return out, obj.get("active_profile")

def save_profiles(profiles: List[Profile], active: Optional[str]) -> None:
    save_json(PROFILES_PATH, {"profiles":[p.__dict__ for p in profiles], "active_profile": active})

def load_watches() -> List[Watch]:
    obj = load_json(WATCHES_PATH, {"watches": []})
    out: List[Watch] = []
    for w in obj.get("watches", []):
        out.append(Watch(
            name=w.get("name","Unnamed Watch"),
            enabled=bool(w.get("enabled", True)),
            source=w.get("source","ftp"),
            path=w.get("path",""),
            kind=w.get("kind","log"),
        ))
    return out

def save_watches(watches: List[Watch]) -> None:
    save_json(WATCHES_PATH, {"watches":[w.__dict__ for w in watches]})

def load_settings() -> dict:
    return load_json(SETTINGS_PATH, {
        "app": {"timeout_seconds": 30, "tick_seconds": 20, "auto_start": False},
        "discord": {"webhook_url":"", "notify_start": True, "notify_success": True, "notify_failure": True, "notify_errors": True}
    })

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

    def pwd(self) -> str:
        return self.ftp.pwd()

    def download(self, remote_full: str, local_path: pathlib.Path) -> None:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        with open(local_path, "wb") as f:
            self.ftp.retrbinary("RETR " + remote_full, f.write)

def discord_post(webhook_url: str, text: str, timeout: int = 15) -> Tuple[bool, str]:
    """Send a Discord webhook message if configured. Returns (ok, details)."""
    webhook_url = (webhook_url or "").strip()
    if not webhook_url:
        return False, "No webhook_url configured"

    # Some networks set system proxy env vars; webhooks can fail via bad proxies.
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    try:
        payload = {"content": text}
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            webhook_url,
            data=data,
            headers={
                "Content-Type": "application/json",
                "User-Agent": f"{APP_NAME}/{APP_VERSION} (+https://github.com/DayZ-AutomationZ)"
            },
            method="POST",
        )
        with opener.open(req, timeout=timeout) as resp:
            code = getattr(resp, "status", 200)
            return (200 <= code < 300), f"HTTP {code}"
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode("utf-8", errors="replace")
        except Exception:
            body = ""
        body = body.strip()
        if len(body) > 400:
            body = body[:400] + "..."
        return False, f"HTTP {e.code} {e.reason}: {body or 'No body'}"
    except Exception as e:
        return False, str(e)

ERROR_KEYS = ["error", "exception", "fatal", "assert", "crash", "segmentation", "stack trace", "script error"]
WARN_KEYS  = ["warning", "warn", "deprecated"]

def classify_lines(lines: List[str]) -> Dict[str, Any]:
    errors = 0
    warns = 0
    crash = 0
    interesting: List[str] = []
    for ln in lines:
        low = ln.lower()
        if any(k in low for k in ERROR_KEYS):
            errors += 1
            interesting.append(ln.strip()[:500])
            if "crash" in low or "fatal" in low or "segmentation" in low:
                crash += 1
        elif any(k in low for k in WARN_KEYS):
            warns += 1
    return {"errors": errors, "warnings": warns, "crash_hits": crash, "interesting": interesting[:20]}

def read_new_tail(path: pathlib.Path, last_offset: int) -> Tuple[List[str], int]:
    if not path.exists():
        return [], last_offset
    size = path.stat().st_size
    if last_offset > size:
        last_offset = 0
    with open(path, "rb") as f:
        f.seek(last_offset)
        chunk = f.read()
        new_offset = f.tell()
    text = chunk.decode("utf-8", errors="replace")
    lines = text.splitlines()
    return lines, new_offset

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.style = apply_dark_theme(self)
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1050x720")
        self.minsize(980, 640)

        for p in [CONFIG_DIR, STATE_DIR, CACHE_DIR, REPORTS_DIR]:
            p.mkdir(parents=True, exist_ok=True)

        self.settings = load_settings()
        self.timeout = int(self.settings.get("app",{}).get("timeout_seconds", 30))
        self.tick_seconds = int(self.settings.get("app",{}).get("tick_seconds", 20))
        self.auto_start = bool(self.settings.get("app",{}).get("auto_start", False))

        self.profiles, self.active_profile = load_profiles()
        self.watches = load_watches()
        self.offsets = load_json(OFFSETS_PATH, {"offsets": {}}).get("offsets", {})
        self.events = load_json(EVENTS_PATH, {"events": []}).get("events", [])
        self.last_scan_ts = None  # updated on each Fetch/monitor cycle

        self.last_scan_ts = None  # updated each Fetch/monitor tick
        self._stop_evt = threading.Event()
        self._thread: Optional[threading.Thread] = None

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_dash = ttk.Frame(nb)
        self.tab_profiles = ttk.Frame(nb)
        self.tab_watches = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        self.tab_help = ttk.Frame(nb)

        nb.add(self.tab_dash, text="Dashboard")
        nb.add(self.tab_profiles, text="Profiles")
        nb.add(self.tab_watches, text="Watches")
        nb.add(self.tab_settings, text="Settings")
        nb.add(self.tab_help, text="Help")

        log_box = ttk.LabelFrame(self, text="Log")
        log_box.pack(fill="both", expand=False, padx=10, pady=8)
        self.log_text = tk.Text(log_box, height=10, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        style_text_widget(self.log_text)
        self.log = Logger(self.log_text)

        self._build_dash()
        self._build_profiles()
        self._build_watches()
        self._build_settings()
        self._build_help()

        self.refresh_profiles_combo()
        self.refresh_profiles_list()
        self.refresh_watches_list()
        self.refresh_events_list()
        self.refresh_status_labels()

        if self.auto_start:
            self.start_monitor()

    def _build_dash(self):
        f = self.tab_dash
        top = ttk.Frame(f); top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Profile:").grid(row=0, column=0, sticky="w")
        self.cmb_profile = ttk.Combobox(top, state="readonly", width=30)
        self.cmb_profile.grid(row=0, column=1, sticky="w", padx=(6,18))

        ttk.Button(top, text="Test Connection", command=self.test_conn, style="Colored.TButton").grid(row=0, column=2, sticky="w", padx=(0,10))
        ttk.Button(top, text="Fetch Now", command=self.fetch_once, style="Colored.TButton").grid(row=0, column=3, sticky="w", padx=(0,10))
        ttk.Button(top, text="Start Monitor", command=self.start_monitor, style="Colored.TButton").grid(row=0, column=4, sticky="w", padx=(0,10))
        ttk.Button(top, text="Stop", command=self.stop_monitor, style="Colored.TButton").grid(row=0, column=5, sticky="w")

        status = ttk.LabelFrame(f, text="Health Summary")
        status.pack(fill="x", expand=False, padx=12, pady=(0,10))

        self.lbl_status = ttk.Label(status, text="Status: -")
        self.lbl_status.grid(row=0, column=0, sticky="w", padx=10, pady=6)

        self.lbl_last_crash = ttk.Label(status, text="Last crash: -")
        self.lbl_last_crash.grid(row=0, column=1, sticky="w", padx=10, pady=6)

        self.lbl_week = ttk.Label(status, text="Crash hits (7d): -")
        self.lbl_week.grid(row=0, column=2, sticky="w", padx=10, pady=6)

        self.lbl_last_change = ttk.Label(status, text="Last event: -")
        self.lbl_last_change.grid(row=1, column=0, sticky="w", padx=10, pady=6, columnspan=3)

        events_box = ttk.LabelFrame(f, text="Recent Events")
        events_box.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.lst_events = tk.Listbox(events_box, height=14, exportselection=False)
        self.lst_events.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_events)

        ttk.Button(f, text="Clear Events", command=self.clear_events, style="Colored.TButton").pack(anchor="w", padx=12, pady=(0,12))

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

    def clear_events(self):
        self.events = []
        save_json(EVENTS_PATH, {"events": self.events})
        self.refresh_events_list()
        self.refresh_status_labels()

    def start_monitor(self):
        if self._thread and self._thread.is_alive():
            return
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()
        self.log.info(f"Monitor started (tick={self.tick_seconds}s).")

    def stop_monitor(self):
        self._stop_evt.set()
        self.log.info("Monitor stopping...")

    def _monitor_loop(self):
        while not self._stop_evt.is_set():
            try:
                self.fetch_once(silent=True)
            except Exception as e:
                self.log.error("Monitor loop error: " + str(e))
            for _ in range(max(1, self.tick_seconds)):
                if self._stop_evt.is_set():
                    break
                time.sleep(1)

    def fetch_once(self, silent: bool = False):
        p = self.selected_profile()
        enabled = [w for w in self.watches if w.enabled]
        if not enabled:
            if not silent:
                messagebox.showwarning("No watches", "No enabled watches. Add watches in Watches tab.")
            return

        d = self.settings.get("discord", {})
        if d.get("notify_start", True):
            ok, msg = discord_post(d.get("webhook_url",""), f"⏳ {APP_NAME}: fetch started ({len(enabled)} watch(es))")
            if not ok:
                self.log.warn("Discord webhook failed: " + msg)

        cli = None
        try:
            if any(w.source == "ftp" for w in enabled):
                if not p:
                    raise RuntimeError("No profile selected for FTP watches.")
                cli = FTPClient(p, self.timeout)
                cli.connect()

            total_errors = 0
            total_warns = 0
            crash_hits = 0

            for w in enabled:
                if w.source == "ftp":
                    root = norm_remote(p.root or "/")
                    remote_full = "/" + (root.rstrip("/") + "/" + norm_remote(w.path)).strip("/")
                    local_name = f"{p.name}__{w.name}".replace(" ", "_").replace("/", "_") + ".log"
                    local_path = CACHE_DIR / local_name
                    cli.download(remote_full, local_path)
                    self.log.info(f"Fetched: {remote_full} -> {local_path.name}")
                    lines, new_off = read_new_tail(local_path, int(self.offsets.get(local_path.name, 0)))
                    self.offsets[local_path.name] = new_off
                else:
                    lp = pathlib.Path(w.path).expanduser()
                    lines, new_off = read_new_tail(lp, int(self.offsets.get(str(lp), 0)))
                    self.offsets[str(lp)] = new_off

                if not lines:
                    continue

                r = classify_lines(lines)
                total_errors += r["errors"]
                total_warns += r["warnings"]
                crash_hits += r["crash_hits"]

                if r["crash_hits"] > 0 or r["errors"] > 0:
                    event = {
                        "ts": datetime.datetime.now().isoformat(timespec="seconds"),
                        "watch": w.name,
                        "source": w.source,
                        "path": w.path,
                        "errors": r["errors"],
                        "warnings": r["warnings"],
                        "crash_hits": r["crash_hits"],
                        "sample": r["interesting"][:5],
                    }
                    self.events.append(event)
                    self.events = self.events[-200:]

            save_json(OFFSETS_PATH, {"offsets": self.offsets})
            save_json(EVENTS_PATH, {"events": self.events})

            self.after(0, self.refresh_events_list)
            self.after(0, self.refresh_status_labels)

            if d.get("notify_errors", True) and (crash_hits > 0 or total_errors > 0):
                ok, msg = discord_post(d.get("webhook_url",""),
                                      f"⚠ {APP_NAME}: detected {total_errors} error(s), {crash_hits} crash hit(s) in latest fetch.")
                if not ok:
                    self.log.warn("Discord webhook failed: " + msg)

            if d.get("notify_success", True):
                ok, msg = discord_post(d.get("webhook_url",""),
                                      f"✅ {APP_NAME}: fetch done. errors={total_errors}, warnings={total_warns}, crash_hits={crash_hits}")
                if not ok:
                    self.log.warn("Discord webhook failed: " + msg)

            if not silent:
                messagebox.showinfo("Done", "Fetch complete.\n"
                                            f"errors={total_errors} warnings={total_warns} crash_hits={crash_hits}")

        except Exception as e:
            self.log.error("Fetch failed: " + str(e))
            self.log.error(traceback.format_exc())
            if d.get("notify_failure", True):
                ok, msg = discord_post(d.get("webhook_url",""), f"❌ {APP_NAME}: fetch FAILED: {e}")
                if not ok:
                    self.log.warn("Discord webhook failed: " + msg)
            if not silent:
                messagebox.showerror("Failed", str(e))
        finally:
            if cli:
                cli.close()

    def refresh_status_labels(self):
        last_event = self.events[-1] if self.events else None
        last_crash = None
        for ev in reversed(self.events):
            if ev.get("crash_hits", 0) > 0:
                last_crash = ev
                break

        week_hits = 0
        now = datetime.datetime.now()
        for ev in self.events:
            try:
                ts = datetime.datetime.fromisoformat(ev["ts"])
            except Exception:
                continue
            if (now - ts).days <= 7:
                week_hits += int(ev.get("crash_hits", 0))

        status = "🟢 Stable"
        if week_hits >= 3:
            status = "🟠 Unstable"
        if week_hits >= 6:
            status = "🔴 Critical"

        self.lbl_status.configure(text=f"Status: {status}")
        if last_crash:
            self.lbl_last_crash.configure(text=f"Last crash: {last_crash['ts']} (watch: {last_crash['watch']})")
        else:
            self.lbl_last_crash.configure(text="Last crash: none detected")
        self.lbl_week.configure(text=f"Crash hits (7d): {week_hits}")

        scan = self.last_scan_ts
        if last_event and scan:
            self.lbl_last_change.configure(text=f"Last scan: {scan} | Last event: {last_event['ts']} | {last_event['watch']} | errors={last_event['errors']} crash_hits={last_event['crash_hits']}")
        elif last_event:
            self.lbl_last_change.configure(text=f"Last event: {last_event['ts']} | {last_event['watch']} | errors={last_event['errors']} crash_hits={last_event['crash_hits']}")
        elif scan:
            self.lbl_last_change.configure(text=f"Last scan: {scan} | Last event: -")
        else:
            self.lbl_last_change.configure(text="Last event: -")

    def refresh_events_list(self):
        self.lst_events.delete(0, "end")
        if not self.events:
            self.lst_events.insert("end", "No events yet (no warnings/errors detected).")
            self.lst_events.insert("end", "Tip: Use 'Fetch Now' or 'Start Monitor'.")
            return
        for ev in reversed(self.events[-80:]):
            ts = ev.get("ts","?")
            w = ev.get("watch","?")
            e = ev.get("errors",0)
            c = ev.get("crash_hits",0)
            self.lst_events.insert("end", f"{ts} | {w} | errors={e} crash_hits={c}")

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

        self.v_name = tk.StringVar()
        self.v_host = tk.StringVar()
        self.v_port = tk.StringVar(value="21")
        self.v_user = tk.StringVar()
        self.v_pass = tk.StringVar()
        self.v_tls  = tk.BooleanVar(value=False)
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
        else:
            self.cmb_profile.set("")

    def refresh_profiles_list(self):
        self.lst_profiles.delete(0, "end")
        for p in self.profiles:
            suffix = " (active)" if self.active_profile == p.name else ""
            self.lst_profiles.insert("end", p.name + suffix)

    def _sel_index(self, lb: tk.Listbox) -> Optional[int]:
        sel = lb.curselection()
        return int(sel[0]) if sel else None

    def on_profile_select(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None: return
        p = self.profiles[idx]
        self.v_name.set(p.name); self.v_host.set(p.host); self.v_port.set(str(p.port))
        self.v_user.set(p.username); self.v_pass.set(p.password); self.v_tls.set(p.tls); self.v_root.set(p.root)

    def profile_new(self):
        n = "Profile_" + str(len(self.profiles) + 1)
        self.profiles.append(Profile(n, "", 21, "", "", False, "/dayzstandalone"))
        self.active_profile = n
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_list(); self.refresh_profiles_combo()

        idx = len(self.profiles) - 1
        self.lst_profiles.selection_clear(0, "end")
        self.lst_profiles.selection_set(idx)
        self.lst_profiles.see(idx)
        self.on_profile_select()

    def profile_delete(self):
        idx = self._sel_index(self.lst_profiles)
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
        if idx is None: return
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

        try:
            idx = [p.name for p in self.profiles].index(new_profile.name)
            self.lst_profiles.selection_clear(0, "end")
            self.lst_profiles.selection_set(idx)
            self.lst_profiles.see(idx)
            self.on_profile_select()
        except Exception:
            pass

        messagebox.showinfo("Saved", "Profile saved.")

    def _build_watches(self):
        f = self.tab_watches
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Watches (logs to monitor)")
        left.pack(side="left", fill="both", expand=False)

        self.lst_watches = tk.Listbox(left, width=60, height=18, exportselection=False)
        self.lst_watches.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_watches)
        self.lst_watches.bind("<<ListboxSelect>>", lambda e: self.on_watch_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.watch_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.watch_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.watch_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Watch details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.w_name = tk.StringVar()
        self.w_enabled = tk.BooleanVar(value=True)
        self.w_source = tk.StringVar(value="ftp")
        self.w_path = tk.StringVar()
        self.w_kind = tk.StringVar(value="log")

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w"); ttk.Entry(form, textvariable=self.w_name, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1
        ttk.Checkbutton(form, text="Enabled", variable=self.w_enabled).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Source").grid(row=r, column=0, sticky="w")
        ttk.Combobox(form, textvariable=self.w_source, state="readonly", values=["ftp","local"], width=12).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Path").grid(row=r, column=0, sticky="w")
        ttk.Entry(form, textvariable=self.w_path, width=56).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Kind").grid(row=r, column=0, sticky="w")
        ttk.Combobox(form, textvariable=self.w_kind, state="readonly", values=["log"], width=12).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="FTP paths are relative to the profile root. Local paths should be absolute.").grid(row=r, column=0, columnspan=2, sticky="w", pady=(10,0)); r+=1

    def refresh_watches_list(self):
        self.lst_watches.delete(0, "end")
        for w in self.watches:
            flag = "ON" if w.enabled else "OFF"
            self.lst_watches.insert("end", f"[{flag}] {w.name} | {w.source}: {w.path}")

    def on_watch_select(self):
        idx = self._sel_index(self.lst_watches)
        if idx is None: return
        w = self.watches[idx]
        self.w_name.set(w.name)
        self.w_enabled.set(w.enabled)
        self.w_source.set(w.source)
        self.w_path.set(w.path)
        self.w_kind.set(w.kind)

    def watch_new(self):
        self.watches.append(Watch(f"Watch_{len(self.watches)+1}", True, "ftp", "", "log"))
        save_watches(self.watches)
        self.refresh_watches_list()

    def watch_delete(self):
        idx = self._sel_index(self.lst_watches)
        if idx is None: return
        w = self.watches[idx]
        if not messagebox.askyesno("Delete", f"Delete watch '{w.name}'?"): return
        del self.watches[idx]
        save_watches(self.watches)
        self.refresh_watches_list()

    def watch_save(self):
        idx = self._sel_index(self.lst_watches)
        if idx is None:
            messagebox.showwarning("No watch", "Select a watch.")
            return
        self.watches[idx] = Watch(
            name=self.w_name.get().strip() or "Unnamed Watch",
            enabled=bool(self.w_enabled.get()),
            source=(self.w_source.get() or "ftp").strip(),
            path=(self.w_path.get() or "").strip(),
            kind=(self.w_kind.get() or "log").strip(),
        )
        save_watches(self.watches)
        self.refresh_watches_list()
        messagebox.showinfo("Saved", "Watch saved.")

    def _build_settings(self):
        f = self.tab_settings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        app_box = ttk.LabelFrame(outer, text="App")
        app_box.pack(fill="x", pady=(0,10))

        self.s_timeout = tk.StringVar(value=str(self.timeout))
        self.s_tick = tk.StringVar(value=str(self.tick_seconds))
        self.s_autostart = tk.BooleanVar(value=self.auto_start)

        ttk.Label(app_box, text="FTP timeout (seconds)").grid(row=0, column=0, sticky="w", padx=10, pady=6)
        ttk.Entry(app_box, textvariable=self.s_timeout, width=10).grid(row=0, column=1, sticky="w", padx=10, pady=6)
        ttk.Label(app_box, text="Monitor tick (seconds)").grid(row=1, column=0, sticky="w", padx=10, pady=6)
        ttk.Entry(app_box, textvariable=self.s_tick, width=10).grid(row=1, column=1, sticky="w", padx=10, pady=6)
        ttk.Checkbutton(app_box, text="Auto-start monitor on launch", variable=self.s_autostart).grid(row=2, column=0, columnspan=2, sticky="w", padx=10, pady=6)

        disc = self.settings.get("discord", {})
        disc_box = ttk.LabelFrame(outer, text="Discord Webhook")
        disc_box.pack(fill="x", pady=(0,10))

        self.s_webhook = tk.StringVar(value=disc.get("webhook_url",""))
        self.s_ds = tk.BooleanVar(value=bool(disc.get("notify_start", True)))
        self.s_dok = tk.BooleanVar(value=bool(disc.get("notify_success", True)))
        self.s_df = tk.BooleanVar(value=bool(disc.get("notify_failure", True)))
        self.s_de = tk.BooleanVar(value=bool(disc.get("notify_errors", True)))

        ttk.Label(disc_box, text="Webhook URL").grid(row=0, column=0, sticky="w", padx=10, pady=6)
        ttk.Entry(disc_box, textvariable=self.s_webhook, width=90).grid(row=0, column=1, sticky="w", padx=10, pady=6)
        ttk.Checkbutton(disc_box, text="Notify start", variable=self.s_ds).grid(row=1, column=0, sticky="w", padx=10, pady=2)
        ttk.Checkbutton(disc_box, text="Notify success", variable=self.s_dok).grid(row=1, column=1, sticky="w", padx=10, pady=2)
        ttk.Checkbutton(disc_box, text="Notify failure", variable=self.s_df).grid(row=2, column=0, sticky="w", padx=10, pady=2)
        ttk.Checkbutton(disc_box, text="Notify errors/crash hits", variable=self.s_de).grid(row=2, column=1, sticky="w", padx=10, pady=2)

        btns = ttk.Frame(outer); btns.pack(fill="x")
        ttk.Button(btns, text="Save Settings", command=self.save_settings_ui, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Test Discord Webhook", command=self.test_discord, style="Colored.TButton").pack(side="left", padx=10)

    def save_settings_ui(self):
        try:
            timeout = int((self.s_timeout.get() or "30").strip())
            tick = int((self.s_tick.get() or "20").strip())
        except ValueError:
            messagebox.showerror("Invalid", "Timeout and tick must be numbers.")
            return
        self.timeout = max(5, timeout)
        self.tick_seconds = max(5, tick)
        self.auto_start = bool(self.s_autostart.get())

        self.settings["app"] = {"timeout_seconds": self.timeout, "tick_seconds": self.tick_seconds, "auto_start": self.auto_start}
        self.settings["discord"] = {
            "webhook_url": (self.s_webhook.get() or "").strip(),
            "notify_start": bool(self.s_ds.get()),
            "notify_success": bool(self.s_dok.get()),
            "notify_failure": bool(self.s_df.get()),
            "notify_errors": bool(self.s_de.get()),
        }
        save_json(SETTINGS_PATH, self.settings)
        messagebox.showinfo("Saved", "Settings saved.")

    def test_discord(self):
        self.save_settings_ui()
        url = self.settings.get("discord", {}).get("webhook_url","")
        ok, msg = discord_post(url, f"✅ {APP_NAME}: Discord webhook test message.")
        if ok:
            messagebox.showinfo("OK", f"Webhook OK ({msg})")
        else:
            messagebox.showwarning("Failed", f"Webhook failed: {msg}")

    def _build_help(self):
        t = tk.Text(self.tab_help, wrap="word")
        t.pack(fill="both", expand=True, padx=12, pady=12)
        style_text_widget(t)
        t.insert("1.0",
            f"{APP_NAME}\n\n"
            f"Version: {APP_VERSION}\n"
            "Created by Danny van den Brande\n\n"
            "This tool monitors server log files (via FTP/FTPS or local paths), detects errors/crash signatures, and can send Discord notifications.\n\n"
            "Quick start:\n"
            "  1) Create a Profile (FTP) if you want to fetch logs from a host.\n"
            "  2) Add Watches (remote log file paths or local paths).\n"
            "  3) Start Monitor on the Dashboard.\n\n"
            "AutomationZ Server Health is free and open-source software.\n\n"
            "If this tool helps you automate server tasks, save time,\n"
            "or manage multiple servers more easily,\n"
            "consider supporting development with a donation.\n\n"
            "Donations are optional, but appreciated and help\n"
            "support ongoing development and improvements.\n\n"
            "Support link:\n"
            "https://ko-fi.com/dannyvandenbrande\n"
        )
        t.configure(state="disabled")

def main():
    for p in [CONFIG_DIR, STATE_DIR, CACHE_DIR, REPORTS_DIR]:
        p.mkdir(parents=True, exist_ok=True)
    App().mainloop()

if __name__ == "__main__":
    main()
