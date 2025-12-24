#!/usr/bin/env python3
from __future__ import annotations

import os
import sys
import json
import time
import socket
import struct
import zlib
import urllib.request
import urllib.parse
import pathlib
import datetime
import traceback
import shutil
from dataclasses import dataclass
from typing import List, Optional, Dict, Any, Tuple

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

APP_NAME = "AutomationZ Admin Orchestrator"
APP_VERSION = "1.1.0"

BASE_DIR = pathlib.Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
LOGS_DIR = BASE_DIR / "logs"
BACKUPS_DIR = BASE_DIR / "backups"
DEFAULT_PRESETS_DIR = BASE_DIR / "presets"

PROFILES_PATH = CONFIG_DIR / "profiles.json"
MAPPINGS_PATH = CONFIG_DIR / "mappings.json"
MAPPINGSETS_PATH = CONFIG_DIR / "mapping_sets.json"
PLANS_PATH = CONFIG_DIR / "plans.json"
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

# ------------------------- helpers -------------------------

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def norm_remote(path: str) -> str:
    # always use forward slashes, no leading slash
    return (path or "").replace("\\", "/").lstrip("/")

def safe_name(s: str) -> str:
    s = (s or "").strip()
    s = "".join(c for c in s if c.isalnum() or c in (" ", "_", "-", ".")).strip()
    return s or "Unnamed"

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

def parse_csv(s: str) -> List[str]:
    return [x.strip() for x in (s or "").split(",") if x.strip()]

def weekday_name(i: int) -> str:
    return ["Mon","Tue","Wed","Thu","Fri","Sat","Sun"][i % 7]

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


# ------------------------- logging -------------------------

class Logger:
    def __init__(self, widget: tk.Text):
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        self.widget = widget
        self.file = LOGS_DIR / ("orchestrator_" + now_stamp() + ".log")
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


# ------------------------- data models -------------------------

@dataclass
class Profile:
    # FTP/FTPS
    name: str
    host: str
    port: int
    username: str
    password: str
    tls: bool
    root: str

    # Local automation (no FTP)
    local_mode: bool
    local_root: str

    # RCON (BattlEye)
    rcon_host: str
    rcon_port: int
    rcon_password: str

    # Nitrado API (optional)
    nitrado_service_id: str
    nitrado_token: str

@dataclass
class Mapping:
    name: str
    local_relpath: str
    remote_path: str
    backup_before_overwrite: bool

@dataclass
class MappingSet:
    name: str
    mapping_names: List[str]

@dataclass
class Plan:
    name: str
    enabled: bool
    targets_csv: str     # comma-separated profile names
    preset: str
    mapping_set: str

    restart_mode: str    # none|rcon|nitrado
    rcon_command: str
    nitrado_message: str

    verify_mode: str     # none|contains|not_contains
    verify_remote_path: str
    verify_keywords_csv: str

    rollback_on_fail: bool

    schedule_enabled: bool
    days: List[int]      # 0=Mon .. 6=Sun
    hour: int
    minute: int
    last_run_key: str    # YYYYMMDD_HHMM


# ------------------------- persistence -------------------------

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

            local_mode=bool(p.get("local_mode", False)),
            local_root=p.get("local_root",""),

            rcon_host=p.get("rcon_host",""),
            rcon_port=int(p.get("rcon_port", 0)),
            rcon_password=p.get("rcon_password",""),

            nitrado_service_id=p.get("nitrado_service_id",""),
            nitrado_token=p.get("nitrado_token",""),
        ))
    return out, obj.get("active_profile")

def save_profiles(profiles: List[Profile], active: Optional[str]) -> None:
    save_json(PROFILES_PATH, {
        "profiles": [p.__dict__ for p in profiles],
        "active_profile": active
    })

def load_mappings() -> List[Mapping]:
    obj = load_json(MAPPINGS_PATH, {"mappings": []})
    out: List[Mapping] = []
    for m in obj.get("mappings", []):
        out.append(Mapping(
            name=m.get("name","Unnamed Mapping"),
            local_relpath=m.get("local_relpath",""),
            remote_path=m.get("remote_path",""),
            backup_before_overwrite=bool(m.get("backup_before_overwrite", True)),
        ))
    return out

def save_mappings(mappings: List[Mapping]) -> None:
    save_json(MAPPINGS_PATH, {"mappings": [m.__dict__ for m in mappings]})

def load_mapping_sets() -> List[MappingSet]:
    obj = load_json(MAPPINGSETS_PATH, {"mapping_sets": []})
    out: List[MappingSet] = []
    for s in obj.get("mapping_sets", []):
        out.append(MappingSet(
            name=s.get("name","Default"),
            mapping_names=list(s.get("mapping_names", [])),
        ))
    return out

def save_mapping_sets(sets_: List[MappingSet]) -> None:
    save_json(MAPPINGSETS_PATH, {"mapping_sets": [s.__dict__ for s in sets_]})

def load_plans() -> List[Plan]:
    obj = load_json(PLANS_PATH, {"plans": []})
    out: List[Plan] = []
    for p in obj.get("plans", []):
        out.append(Plan(
            name=p.get("name","Unnamed Plan"),
            enabled=bool(p.get("enabled", True)),
            targets_csv=p.get("targets_csv",""),
            preset=p.get("preset",""),
            mapping_set=p.get("mapping_set","Default"),

            restart_mode=p.get("restart_mode","none"),
            rcon_command=p.get("rcon_command","#shutdown"),
            nitrado_message=p.get("nitrado_message","AutomationZ restart"),

            verify_mode=p.get("verify_mode","none"),
            verify_remote_path=p.get("verify_remote_path",""),
            verify_keywords_csv=p.get("verify_keywords_csv",""),

            rollback_on_fail=bool(p.get("rollback_on_fail", True)),

            schedule_enabled=bool(p.get("schedule_enabled", False)),
            days=list(p.get("days", [0,1,2,3,4,5,6])),
            hour=int(p.get("hour", 0)),
            minute=int(p.get("minute", 0)),
            last_run_key=p.get("last_run_key",""),
        ))
    return out

def save_plans(plans: List[Plan]) -> None:
    save_json(PLANS_PATH, {"plans": [p.__dict__ for p in plans]})

def load_settings() -> Dict[str, Any]:
    # Merge defaults to avoid KeyErrors across versions.
    defaults = {
        "app": {"timeout_seconds": 25, "tick_seconds": 15},
        "discord": {"webhook_url": "", "notify_start": True, "notify_success": True, "notify_failure": True, "username": "AutomationZ"},
        "paths": {"presets_dir": ""},
        "host_type": "dedicated"  # dedicated|nitrado
    }
    obj = load_json(SETTINGS_PATH, defaults)
    # shallow merge
    for k, v in defaults.items():
        if k not in obj or not isinstance(obj.get(k), dict) and isinstance(v, dict):
            obj[k] = v
    # ensure subkeys
    for section in ("app", "discord", "paths"):
        obj.setdefault(section, {})
        for kk, vv in defaults[section].items():
            obj[section].setdefault(kk, vv)
    obj.setdefault("host_type", defaults["host_type"])
    save_json(SETTINGS_PATH, obj)
    return obj

def presets_dir_from_settings(settings: Dict[str, Any]) -> pathlib.Path:
    p = (settings.get("paths", {}) or {}).get("presets_dir", "") or ""
    p = str(p).strip()
    if p:
        try:
            return pathlib.Path(p).expanduser().resolve()
        except Exception:
            return DEFAULT_PRESETS_DIR
    return DEFAULT_PRESETS_DIR


# ------------------------- Discord webhook -------------------------

class Discord:
    def __init__(self, settings: Dict[str, Any], log: Logger):
        self.settings = settings
        self.log = log

    def post(self, content: str) -> None:
        try:
            d = self.settings.get("discord", {}) or {}
            url = (d.get("webhook_url") or "").strip()
            if not url:
                return
            payload: Dict[str, Any] = {"content": content}
            username = (d.get("username") or "").strip()
            if username:
                payload["username"] = username

            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                url=url,
                data=data,
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "User-Agent": "AutomationZ/1.0 (+https://github.com/DayZ-AutomationZ)"
                }
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                _ = resp.read()
        except Exception as e:
            self.log.warn("Discord webhook failed: " + str(e))


# ------------------------- FTP client -------------------------

import ftplib

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


# ------------------------- Local apply -------------------------

def local_apply(profile: Profile, mappings: List[Mapping], preset_dir: pathlib.Path, backups_root: pathlib.Path, log: Logger) -> None:
    root = pathlib.Path(profile.local_root or "").expanduser().resolve()
    if not root.exists():
        raise RuntimeError(f"Local root folder not found: {root}")

    for m in mappings:
        src = (preset_dir / m.local_relpath).resolve()
        dest = (root / norm_remote(m.remote_path)).resolve()

        # Safety: ensure dest stays inside root
        try:
            dest.relative_to(root)
        except Exception:
            raise RuntimeError(f"Unsafe local destination (outside root): {dest}")

        if m.backup_before_overwrite and dest.exists() and dest.is_file():
            bpath = backups_root / norm_remote(m.remote_path)
            bpath.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(dest, bpath)
            log.info(f"Local backup OK: {dest} -> {bpath}")

        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        log.info(f"Local applied: {src} -> {dest}")


# ------------------------- BE RCON (UDP) -------------------------

class BERcon:
    """
    Minimal BattlEye RCon client (UDP).
    Spec: https://www.battleye.com/downloads/BERConProtocol.txt
    """

    def __init__(self, host: str, port: int, password: str, timeout: float = 6.0):
        self.host = host
        self.port = int(port)
        self.password = password
        self.timeout = timeout
        self.sock: Optional[socket.socket] = None
        self.seq = 0

    @staticmethod
    def _packet(payload: bytes) -> bytes:
        data = b"\xFF" + payload
        crc = zlib.crc32(data) & 0xFFFFFFFF
        return b"BE" + struct.pack("<I", crc) + data

    @staticmethod
    def _unpack(pkt: bytes) -> Optional[bytes]:
        if not pkt or len(pkt) < 7:
            return None
        if pkt[0:2] != b"BE":
            return None
        if pkt[6:7] != b"\xFF":
            return None
        return pkt[7:]

    def connect(self) -> None:
        if not self.host or not self.port:
            raise RuntimeError("RCON host/port not set.")
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.settimeout(self.timeout)
        self.sock.sendto(self._packet(b"\x00" + self.password.encode("ascii", "ignore")), (self.host, self.port))
        payload = self._recv_payload()
        if not payload or payload[0:1] != b"\x00":
            raise RuntimeError("RCON: no login response.")
        ok = payload[1:2] == b"\x01"
        if not ok:
            raise RuntimeError("RCON: login failed (wrong password?)")

    def close(self) -> None:
        try:
            if self.sock:
                self.sock.close()
        finally:
            self.sock = None

    def _recv_payload(self) -> Optional[bytes]:
        if not self.sock:
            return None
        try:
            pkt, _ = self.sock.recvfrom(4096)
            return self._unpack(pkt)
        except socket.timeout:
            return None

    def command(self, cmd: str) -> str:
        if not self.sock:
            raise RuntimeError("RCON not connected.")
        cmd = (cmd or "").strip()
        payload = b"\x01" + bytes([self.seq & 0xFF]) + cmd.encode("ascii", "ignore")
        self.sock.sendto(self._packet(payload), (self.host, self.port))

        full = b""
        expected_packets = None
        got_packets: Dict[int, bytes] = {}
        t0 = time.time()

        while time.time() - t0 < self.timeout:
            p = self._recv_payload()
            if not p:
                break

            if p[0:1] == b"\x02":
                seq = p[1:2]
                ack = b"\x02" + seq
                self.sock.sendto(self._packet(ack), (self.host, self.port))
                continue

            if p[0:1] != b"\x01":
                continue
            if p[1:2] != bytes([self.seq & 0xFF]):
                continue

            rest = p[2:]
            if rest.startswith(b"\x00") and len(rest) >= 3:
                expected_packets = rest[1]
                idx = rest[2]
                got_packets[int(idx)] = rest[3:]
                if expected_packets is not None and len(got_packets) == expected_packets:
                    full = b"".join(got_packets[i] for i in sorted(got_packets.keys()))
                    break
            else:
                full = rest
                break

        self.seq = (self.seq + 1) & 0xFF
        try:
            return full.decode("utf-8", "ignore")
        except Exception:
            return ""


# ------------------------- Nitrado API -------------------------

def nitrado_restart(service_id: str, token: str, message: str, timeout: int = 20) -> None:
    if not service_id or not token:
        raise RuntimeError("Nitrado service_id/token not set.")
    base = f"https://api.nitrado.net/services/{service_id}/gameservers/restart"
    qs = urllib.parse.urlencode({
        "message": message or "AutomationZ restart",
        "restart_message": "Server restarting..."
    })
    url = base + "?" + qs
    req = urllib.request.Request(
        url=url,
        method="POST",
        headers={
            "Authorization": "Bearer " + token.strip(),
            "User-Agent": "AutomationZ/1.0 (+https://github.com/DayZ-AutomationZ)",
            "Accept": "application/json",
        },
        data=b""
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        _ = resp.read()


# ------------------------- Orchestrator core -------------------------

class Orchestrator:
    def __init__(self, settings: Dict[str, Any], log: Logger):
        self.settings = settings
        self.log = log
        self.discord = Discord(settings, log)

    def _notify(self, kind: str, text: str) -> None:
        d = self.settings.get("discord", {}) or {}
        if kind == "start" and not d.get("notify_start", True):
            return
        if kind == "success" and not d.get("notify_success", True):
            return
        if kind == "failure" and not d.get("notify_failure", True):
            return
        self.discord.post(text)

    def run_plan(self, plan: Plan, profiles: List[Profile], mappings: List[Mapping], sets_: List[MappingSet], presets_dir: pathlib.Path) -> None:
        if not plan.enabled:
            self.log.warn(f"Plan '{plan.name}' is disabled. Skipping.")
            return

        targets = parse_csv(plan.targets_csv)
        if not targets:
            self.log.warn(f"Plan '{plan.name}' has no targets.")
            return

        preset = (plan.preset or "").strip()
        if not preset:
            self.log.warn(f"Plan '{plan.name}' has no preset selected.")
            return
        preset_dir = presets_dir / preset
        if not preset_dir.exists():
            self.log.error(f"Preset folder missing: {preset_dir}")
            return

        mapping_set = next((s for s in sets_ if s.name == plan.mapping_set), None)
        if not mapping_set:
            self.log.error(f"Mapping set not found: {plan.mapping_set}")
            return

        chosen_mappings = [m for m in mappings if m.name in set(mapping_set.mapping_names)]
        if not chosen_mappings:
            self.log.error(f"Mapping set '{mapping_set.name}' is empty.")
            return

        missing = [m.local_relpath for m in chosen_mappings if not (preset_dir / m.local_relpath).exists()]
        if missing:
            self.log.error("Missing in preset:\n" + "\n".join(missing))
            return

        self._notify("start", f"🚀 **AutomationZ** plan started: **{plan.name}**\nTargets: {', '.join(targets)}\nPreset: `{preset}`\nRestart: `{plan.restart_mode}`")

        for tname in targets:
            prof = next((p for p in profiles if p.name == tname), None)
            if not prof:
                self.log.error(f"Target profile not found: {tname}")
                continue
            try:
                self._run_plan_for_profile(plan, prof, chosen_mappings, preset_dir)
                self.log.info(f"Plan OK: {plan.name} -> {prof.name}")
            except Exception as e:
                self.log.error(f"Plan FAILED: {plan.name} -> {prof.name} :: {e}")
                self.log.error(traceback.format_exc())
                self._notify("failure", f"❌ **AutomationZ** plan failed: **{plan.name}**\nProfile: **{prof.name}**\nError: `{e}`")

        self._notify("success", f"✅ **AutomationZ** plan finished: **{plan.name}**")

    def _run_plan_for_profile(self, plan: Plan, prof: Profile, chosen_mappings: List[Mapping], preset_dir: pathlib.Path) -> None:
        timeout = int((self.settings.get("app", {}) or {}).get("timeout_seconds", 25))

        backups_root = BACKUPS_DIR / safe_name(prof.name) / safe_name(plan.name) / now_stamp()
        backups_root.mkdir(parents=True, exist_ok=True)

        if prof.local_mode:
            self.log.info(f"Local mode: applying into {prof.local_root}")
            local_apply(prof, chosen_mappings, preset_dir, backups_root, self.log)
        else:
            root = norm_remote(prof.root or "/")
            cli = FTPClient(prof, timeout)
            cli.connect()
            try:
                for m in chosen_mappings:
                    local_file = preset_dir / m.local_relpath
                    remote_full = "/" + (root.rstrip("/") + "/" + norm_remote(m.remote_path)).strip("/")

                    if m.backup_before_overwrite:
                        bpath = backups_root / norm_remote(m.remote_path)
                        ok = cli.download(remote_full, bpath)
                        if ok:
                            self.log.info(f"Backup OK: {remote_full} -> {bpath}")
                        else:
                            self.log.warn(f"Backup skipped/failed: {remote_full}")

                    cli.upload(local_file, remote_full)
                    self.log.info(f"Uploaded: {local_file} -> {remote_full}")
            finally:
                cli.close()

        # restart stage (still remote features)
        if plan.restart_mode == "rcon":
            self.log.info(f"RCON restart: {prof.rcon_host}:{prof.rcon_port} cmd={plan.rcon_command}")
            r = BERcon(prof.rcon_host or prof.host, int(prof.rcon_port or 0), prof.rcon_password, timeout=8.0)
            r.connect()
            try:
                _ = r.command(plan.rcon_command or "#shutdown")
            finally:
                r.close()

        elif plan.restart_mode == "nitrado":
            self.log.info(f"Nitrado restart: service_id={prof.nitrado_service_id}")
            nitrado_restart(prof.nitrado_service_id, prof.nitrado_token, plan.nitrado_message or "AutomationZ restart", timeout=timeout)

        # verify stage (FTP only)
        if (not prof.local_mode) and plan.verify_mode and plan.verify_mode != "none":
            self._verify_after(plan, prof)

    def _verify_after(self, plan: Plan, prof: Profile) -> None:
        timeout = int((self.settings.get("app", {}) or {}).get("timeout_seconds", 25))
        root = norm_remote(prof.root or "/")
        remote_full = "/" + (root.rstrip("/") + "/" + norm_remote(plan.verify_remote_path)).strip("/")
        keywords = parse_csv(plan.verify_keywords_csv)

        tmp_dir = BACKUPS_DIR / "_verify_tmp" / now_stamp()
        tmp_dir.mkdir(parents=True, exist_ok=True)
        tmp_file = tmp_dir / pathlib.Path(plan.verify_remote_path).name

        cli = FTPClient(prof, timeout)
        cli.connect()
        try:
            ok = cli.download(remote_full, tmp_file)
            if not ok:
                raise RuntimeError(f"Verify download failed: {remote_full}")
        finally:
            cli.close()

        text = tmp_file.read_text(encoding="utf-8", errors="ignore")
        hit = any(k.lower() in text.lower() for k in keywords) if keywords else False

        if plan.verify_mode == "contains":
            if not hit:
                raise RuntimeError("Verify failed: none of the keywords were found.")
            self.log.info("Verify OK: keyword found.")
        elif plan.verify_mode == "not_contains":
            if hit:
                raise RuntimeError("Verify failed: forbidden keyword found.")
            self.log.info("Verify OK: forbidden keyword not found.")


# ------------------------- UI -------------------------

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.style = apply_dark_theme(self)
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1120x760")
        self.minsize(980, 640)

        self.settings = load_settings()
        self.presets_dir = presets_dir_from_settings(self.settings)
        self.timeout = int((self.settings.get("app", {}) or {}).get("timeout_seconds", 25))
        self.tick_seconds = int((self.settings.get("app", {}) or {}).get("tick_seconds", 15))

        self.profiles, self.active_profile = load_profiles()
        self.mappings = load_mappings()
        self.mapping_sets = load_mapping_sets()
        self.plans = load_plans()

        if not self.mapping_sets:
            self.mapping_sets = [MappingSet("Default", [m.name for m in self.mappings])]
            save_mapping_sets(self.mapping_sets)

        self._running = False

        nb = ttk.Notebook(self)
        nb.pack(fill="both", expand=True)

        self.tab_dashboard = ttk.Frame(nb)
        self.tab_profiles = ttk.Frame(nb)
        self.tab_mappings = ttk.Frame(nb)
        self.tab_sets = ttk.Frame(nb)
        self.tab_plans = ttk.Frame(nb)
        self.tab_settings = ttk.Frame(nb)
        self.tab_help = ttk.Frame(nb)

        nb.add(self.tab_dashboard, text="Dashboard")
        nb.add(self.tab_profiles, text="Profiles")
        nb.add(self.tab_mappings, text="Mappings")
        nb.add(self.tab_sets, text="Mapping Sets")
        nb.add(self.tab_plans, text="Plans & Schedule")
        nb.add(self.tab_settings, text="Settings")
        nb.add(self.tab_help, text="Help")

        log_box = ttk.LabelFrame(self, text="Log")
        log_box.pack(fill="both", expand=False, padx=10, pady=8)
        self.log_text = tk.Text(log_box, height=10, wrap="word", state="disabled")
        self.log_text.pack(fill="both", expand=True, padx=6, pady=6)
        style_text_widget(self.log_text)
        self.log = Logger(self.log_text)
        self.orch = Orchestrator(self.settings, self.log)

        self._build_dashboard()
        self._build_profiles()
        self._build_mappings()
        self._build_sets()
        self._build_plans()
        self._build_settings()
        self._build_help()

        self.refresh_profiles_ui()
        self.refresh_mappings_ui()
        self.refresh_sets_ui()
        self.refresh_plans_ui()
        self.refresh_presets_ui()

        self.after(1000, self._tick)

    # ---------------- Dashboard ----------------

    def _build_dashboard(self):
        f = self.tab_dashboard
        top = ttk.Frame(f); top.pack(fill="x", padx=12, pady=10)

        ttk.Label(top, text="Plan:").grid(row=0, column=0, sticky="w")
        self.cmb_plan = ttk.Combobox(top, state="readonly", width=40)
        self.cmb_plan.grid(row=0, column=1, sticky="w", padx=(6,18))

        ttk.Button(top, text="Run Plan Now", command=self.run_selected_plan, style="Colored.TButton").grid(row=0, column=2, sticky="w", padx=(0,10))
        self.btn_start = ttk.Button(top, text="Start Scheduler", command=self.toggle_scheduler, style="Colored.TButton")
        self.btn_start.grid(row=0, column=3, sticky="w")

        status = ttk.LabelFrame(f, text="Next / Status")
        status.pack(fill="both", expand=True, padx=12, pady=(0,10))
        self.txt_status = tk.Text(status, height=18, wrap="word", state="disabled")
        self.txt_status.pack(fill="both", expand=True, padx=8, pady=8)
        style_text_widget(self.txt_status)

        quick = ttk.Frame(f); quick.pack(fill="x", padx=12, pady=(0,10))
        ttk.Button(quick, text="Open Presets", command=lambda: self._open_safe(self.presets_dir), style="Colored.TButton").pack(side="left")
        ttk.Button(quick, text="Open Backups", command=lambda: self._open_safe(BACKUPS_DIR), style="Colored.TButton").pack(side="left", padx=8)
        ttk.Button(quick, text="Open Logs", command=lambda: self._open_safe(LOGS_DIR), style="Colored.TButton").pack(side="left")

    def _open_safe(self, path: pathlib.Path) -> None:
        try:
            open_path(path)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def refresh_presets_ui(self):
        self.presets_dir.mkdir(parents=True, exist_ok=True)
        presets = [p.name for p in sorted(self.presets_dir.iterdir()) if p.is_dir()]
        self._all_presets = presets

    def run_selected_plan(self):
        name = (self.cmb_plan.get() or "").strip()
        plan = next((p for p in self.plans if p.name == name), None)
        if not plan:
            messagebox.showwarning("No plan", "Select a plan first.")
            return
        if not messagebox.askyesno("Confirm", f"Run plan '{plan.name}' now?"):
            return
        try:
            self.orch.run_plan(plan, self.profiles, self.mappings, self.mapping_sets, self.presets_dir)
        except Exception as e:
            self.log.error(str(e))

    def toggle_scheduler(self):
        self._running = not self._running
        self.btn_start.configure(text=("Stop Scheduler" if self._running else "Start Scheduler"))
        self.log.info("Scheduler " + ("started." if self._running else "stopped."))

    def _tick(self):
        try:
            self._update_status()
            if self._running:
                self._run_due_plans()
        except Exception as e:
            self.log.error("Scheduler tick error: " + str(e))
        finally:
            self.after(max(5, self.tick_seconds) * 1000, self._tick)

    def _run_due_plans(self):
        now = datetime.datetime.now()
        key = now.strftime("%Y%m%d_%H%M")
        dow = (now.weekday())  # 0..6
        changed = False

        for p in self.plans:
            if not p.enabled or not p.schedule_enabled:
                continue
            if dow not in p.days:
                continue
            if now.hour != int(p.hour) or now.minute != int(p.minute):
                continue
            if p.last_run_key == key:
                continue

            self.log.info(f"Due plan: {p.name} at {key}")
            try:
                self.orch.run_plan(p, self.profiles, self.mappings, self.mapping_sets, self.presets_dir)
            finally:
                p.last_run_key = key
                changed = True

        if changed:
            save_plans(self.plans)

    def _update_status(self):
        lines = []
        now = datetime.datetime.now()
        lines.append(f"Presets folder: {self.presets_dir}")
        lines.append(f"Scheduler: {'RUNNING' if self._running else 'STOPPED'}")
        lines.append(f"Now: {now.strftime('%Y-%m-%d %H:%M:%S')}")
        lines.append("")

        due_list = []
        for p in self.plans:
            if not p.enabled or not p.schedule_enabled:
                continue
            days = ",".join(weekday_name(d) for d in p.days) if p.days else "None"
            due_list.append(f"- {p.name} @ {p.hour:02d}:{p.minute:02d} [{days}] (restart={p.restart_mode})")

        lines.append("Scheduled plans:")
        lines.extend(due_list or ["- (none)"])

        self.txt_status.configure(state="normal")
        self.txt_status.delete("1.0", "end")
        self.txt_status.insert("1.0", "\n".join(lines))
        self.txt_status.configure(state="disabled")

    # ---------------- Profiles ----------------

    def _build_profiles(self):
        f = self.tab_profiles
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Profiles")
        left.pack(side="left", fill="both", expand=False)

        self.lst_profiles = tk.Listbox(left, width=32, height=18, exportselection=False)
        self.lst_profiles.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_profiles)
        self.lst_profiles.bind("<<ListboxSelect>>", lambda e: self.on_profile_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.profile_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.profile_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.profile_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Profile details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self.vp_name = tk.StringVar()
        self.vp_host = tk.StringVar()
        self.vp_port = tk.StringVar(value="21")
        self.vp_user = tk.StringVar()
        self.vp_pass = tk.StringVar()
        self.vp_tls  = tk.BooleanVar(value=False)
        self.vp_root = tk.StringVar(value="/dayzstandalone")

        self.vp_local_mode = tk.BooleanVar(value=False)
        self.vp_local_root = tk.StringVar()

        self.vp_rcon_host = tk.StringVar()
        self.vp_rcon_port = tk.StringVar(value="0")
        self.vp_rcon_pass = tk.StringVar()

        self.vp_nitrado_sid = tk.StringVar()
        self.vp_nitrado_tok = tk.StringVar()

        self._profiles_selected: Optional[int] = None

        def entry(row, label, var, width=48, show=None):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=2)
            e = ttk.Entry(form, textvariable=var, width=width, show=show)
            e.grid(row=row, column=1, sticky="w", pady=2)
            e.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_profiles, self._profiles_selected))
            return e

        r=0
        entry(r, "Name", self.vp_name); r+=1
        entry(r, "FTP Host", self.vp_host); r+=1
        entry(r, "FTP Port", self.vp_port, width=12); r+=1
        entry(r, "FTP Username", self.vp_user); r+=1
        entry(r, "FTP Password", self.vp_pass, show="*"); r+=1
        cb = ttk.Checkbutton(form, text="Use FTPS (TLS)", variable=self.vp_tls)
        cb.grid(row=r, column=1, sticky="w", pady=2); cb.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_profiles, self._profiles_selected)); r+=1
        entry(r, "Remote root", self.vp_root); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        cb2 = ttk.Checkbutton(form, text="Local mode (no FTP) — apply mappings to a local folder", variable=self.vp_local_mode)
        cb2.grid(row=r, column=1, sticky="w", pady=2); cb2.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_profiles, self._profiles_selected)); r+=1
        entry(r, "Local root folder (local mode)", self.vp_local_root, width=60); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        entry(r, "RCON Host (optional)", self.vp_rcon_host); r+=1
        entry(r, "RCON Port (e.g. 12303)", self.vp_rcon_port, width=12); r+=1
        entry(r, "RCON Password", self.vp_rcon_pass, show="*"); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        entry(r, "Nitrado Service ID (optional)", self.vp_nitrado_sid); r+=1
        entry(r, "Nitrado Lifelong Token (optional)", self.vp_nitrado_tok, width=60, show="*"); r+=1

    def refresh_profiles_ui(self):
        self.lst_profiles.delete(0, "end")
        for p in self.profiles:
            tag = "LOCAL" if p.local_mode else "FTP"
            self.lst_profiles.insert("end", f"{p.name} [{tag}]")
        self.cmb_plan["values"] = [p.name for p in self.plans]
        if self.plans and (self.cmb_plan.get() not in [p.name for p in self.plans]):
            self.cmb_plan.set(self.plans[0].name)

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

    def on_profile_select(self):
        idx = self._sel_index(self.lst_profiles)
        self._profiles_selected = idx
        if idx is None:
            return
        p = self.profiles[idx]
        self.vp_name.set(p.name)
        self.vp_host.set(p.host)
        self.vp_port.set(str(p.port))
        self.vp_user.set(p.username)
        self.vp_pass.set(p.password)
        self.vp_tls.set(p.tls)
        self.vp_root.set(p.root)

        self.vp_local_mode.set(p.local_mode)
        self.vp_local_root.set(p.local_root)

        self.vp_rcon_host.set(p.rcon_host)
        self.vp_rcon_port.set(str(p.rcon_port))
        self.vp_rcon_pass.set(p.rcon_password)

        self.vp_nitrado_sid.set(p.nitrado_service_id)
        self.vp_nitrado_tok.set(p.nitrado_token)

    def profile_new(self):
        self.profiles.append(Profile(
            name=f"Profile_{len(self.profiles)+1}",
            host="", port=21, username="", password="", tls=False, root="/dayzstandalone",
            local_mode=False, local_root="",
            rcon_host="", rcon_port=0, rcon_password="",
            nitrado_service_id="", nitrado_token=""
        ))
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_ui()
        idx = len(self.profiles)-1
        self.lst_profiles.selection_set(idx)
        self.on_profile_select()

    def profile_delete(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None:
            return
        p = self.profiles[idx]
        if not messagebox.askyesno("Delete", f"Delete profile '{p.name}'?"):
            return
        del self.profiles[idx]
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_ui()

    def profile_save(self):
        idx = self._sel_index(self.lst_profiles)
        if idx is None:
            messagebox.showwarning("No profile", "Select a profile first.")
            return
        try:
            port = int((self.vp_port.get() or "21").strip())
        except ValueError:
            messagebox.showerror("Invalid", "FTP port must be a number.")
            return
        try:
            rport = int((self.vp_rcon_port.get() or "0").strip())
        except ValueError:
            messagebox.showerror("Invalid", "RCON port must be a number.")
            return
        self.profiles[idx] = Profile(
            name=self.vp_name.get().strip() or self.profiles[idx].name,
            host=self.vp_host.get().strip(),
            port=port,
            username=self.vp_user.get().strip(),
            password=self.vp_pass.get(),
            tls=bool(self.vp_tls.get()),
            root=self.vp_root.get().strip() or "/",

            local_mode=bool(self.vp_local_mode.get()),
            local_root=self.vp_local_root.get().strip(),

            rcon_host=self.vp_rcon_host.get().strip(),
            rcon_port=rport,
            rcon_password=self.vp_rcon_pass.get(),

            nitrado_service_id=self.vp_nitrado_sid.get().strip(),
            nitrado_token=self.vp_nitrado_tok.get().strip(),
        )
        save_profiles(self.profiles, self.active_profile)
        self.refresh_profiles_ui()
        messagebox.showinfo("Saved", "Profile saved.")

    # ---------------- Mappings ----------------

    def _build_mappings(self):
        f = self.tab_mappings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Mappings")
        left.pack(side="left", fill="both", expand=False)

        self.lst_mappings = tk.Listbox(left, width=60, height=18, exportselection=False)
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

        self._mappings_selected: Optional[int] = None

        self.vm_name = tk.StringVar()
        self.vm_local = tk.StringVar()
        self.vm_remote = tk.StringVar()
        self.vm_backup = tk.BooleanVar(value=True)

        def entry(row, label, var, width=62):
            ttk.Label(form, text=label).grid(row=row, column=0, sticky="w", pady=2)
            e = ttk.Entry(form, textvariable=var, width=width)
            e.grid(row=row, column=1, sticky="w", pady=2)
            e.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_mappings, self._mappings_selected))
            return e

        r=0
        entry(r, "Name", self.vm_name); r+=1
        entry(r, "Local relpath (inside preset)", self.vm_local); r+=1
        entry(r, "Remote path (relative to profile root OR local root)", self.vm_remote); r+=1
        cb = ttk.Checkbutton(form, text="Backup before overwrite", variable=self.vm_backup)
        cb.grid(row=r, column=1, sticky="w", pady=2); cb.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_mappings, self._mappings_selected)); r+=1

    def refresh_mappings_ui(self):
        self.lst_mappings.delete(0, "end")
        for m in self.mappings:
            b = "BKP" if m.backup_before_overwrite else "NO-BKP"
            self.lst_mappings.insert("end", f"{m.name} | {m.local_relpath} -> {m.remote_path} [{b}]")
        self.refresh_sets_ui()
        self.refresh_plans_ui()

    def on_mapping_select(self):
        idx = self._sel_index(self.lst_mappings)
        self._mappings_selected = idx
        if idx is None:
            return
        m = self.mappings[idx]
        self.vm_name.set(m.name)
        self.vm_local.set(m.local_relpath)
        self.vm_remote.set(m.remote_path)
        self.vm_backup.set(m.backup_before_overwrite)

    def mapping_new(self):
        self.mappings.append(Mapping(f"Mapping_{len(self.mappings)+1}", "", "", True))
        save_mappings(self.mappings)
        self.refresh_mappings_ui()

    def mapping_delete(self):
        idx = self._sel_index(self.lst_mappings)
        if idx is None:
            return
        m = self.mappings[idx]
        if not messagebox.askyesno("Delete", f"Delete mapping '{m.name}'?"):
            return
        del self.mappings[idx]
        save_mappings(self.mappings)
        for s in self.mapping_sets:
            s.mapping_names = [n for n in s.mapping_names if n != m.name]
        save_mapping_sets(self.mapping_sets)
        self.refresh_mappings_ui()

    def mapping_save(self):
        idx = self._sel_index(self.lst_mappings)
        if idx is None:
            messagebox.showwarning("No mapping", "Select a mapping first.")
            return
        self.mappings[idx] = Mapping(
            name=self.vm_name.get().strip() or self.mappings[idx].name,
            local_relpath=self.vm_local.get().strip(),
            remote_path=self.vm_remote.get().strip(),
            backup_before_overwrite=bool(self.vm_backup.get()),
        )
        save_mappings(self.mappings)
        self.refresh_mappings_ui()
        messagebox.showinfo("Saved", "Mapping saved.")

    # ---------------- Mapping Sets ----------------

    def _build_sets(self):
        f = self.tab_sets
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Mapping sets")
        left.pack(side="left", fill="both", expand=False)

        self.lst_sets = tk.Listbox(left, width=34, height=18, exportselection=False)
        self.lst_sets.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_sets)
        self.lst_sets.bind("<<ListboxSelect>>", lambda e: self.on_set_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.set_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.set_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.set_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Set contents")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self._sets_selected: Optional[int] = None
        self.vs_name = tk.StringVar()

        ttk.Label(form, text="Set name").grid(row=0, column=0, sticky="w", pady=2)
        e = ttk.Entry(form, textvariable=self.vs_name, width=44)
        e.grid(row=0, column=1, sticky="w", pady=2)
        e.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_sets, self._sets_selected))

        # Scrollable checkbox area
        container = ttk.Frame(form)
        container.grid(row=1, column=1, sticky="nsew", pady=(10, 2))

        canvas = tk.Canvas(container, height=420, bg=C_BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(container, orient="vertical", command=canvas.yview)

        self.chk_frame = ttk.Frame(canvas)

        self.chk_frame.bind(
        "<Configure>",
        lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.chk_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        self._set_checks: Dict[str, tk.BooleanVar] = {}

    def refresh_sets_ui(self):
        self.lst_sets.delete(0, "end")
        for s in self.mapping_sets:
            self.lst_sets.insert("end", s.name)
        if hasattr(self, "cmb_plan_set"):
            self.cmb_plan_set["values"] = [s.name for s in self.mapping_sets]

    def on_set_select(self):
        idx = self._sel_index(self.lst_sets)
        self._sets_selected = idx
        if idx is None:
            return
        s = self.mapping_sets[idx]
        self.vs_name.set(s.name)

        for w in list(self.chk_frame.winfo_children()):
            w.destroy()
        self._set_checks.clear()

        names = [m.name for m in self.mappings]
        included = set(s.mapping_names)

        r = 0
        for n in names:
            v = tk.BooleanVar(value=(n in included))
            self._set_checks[n] = v
            cb = ttk.Checkbutton(self.chk_frame, text=n, variable=v)
            cb.grid(row=r, column=0, sticky="w", pady=1)
            cb.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_sets, self._sets_selected))
            r += 1

    def set_new(self):
        self.mapping_sets.append(MappingSet(f"Set_{len(self.mapping_sets)+1}", []))
        save_mapping_sets(self.mapping_sets)
        self.refresh_sets_ui()

    def set_delete(self):
        idx = self._sel_index(self.lst_sets)
        if idx is None:
            return
        s = self.mapping_sets[idx]
        if s.name == "Default":
            messagebox.showwarning("Blocked", "Default set cannot be deleted.")
            return
        if not messagebox.askyesno("Delete", f"Delete set '{s.name}'?"):
            return
        del self.mapping_sets[idx]
        save_mapping_sets(self.mapping_sets)
        for p in self.plans:
            if p.mapping_set == s.name:
                p.mapping_set = "Default"
        save_plans(self.plans)
        self.refresh_sets_ui()
        self.refresh_plans_ui()

    def set_save(self):
        idx = self._sel_index(self.lst_sets)
        if idx is None:
            messagebox.showwarning("No set", "Select a set first.")
            return
        s = self.mapping_sets[idx]
        new_name = self.vs_name.get().strip() or s.name
        chosen = [n for n, v in self._set_checks.items() if bool(v.get())]

        old_name = s.name
        s.name = new_name
        s.mapping_names = chosen

        if old_name != new_name:
            for p in self.plans:
                if p.mapping_set == old_name:
                    p.mapping_set = new_name
            save_plans(self.plans)

        save_mapping_sets(self.mapping_sets)
        self.refresh_sets_ui()
        messagebox.showinfo("Saved", "Mapping set saved.")

    # ---------------- Plans ----------------

    def _build_plans(self):
        f = self.tab_plans
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        left = ttk.LabelFrame(outer, text="Plans")
        left.pack(side="left", fill="both", expand=False)

        self.lst_plans = tk.Listbox(left, width=40, height=18, exportselection=False)
        self.lst_plans.pack(fill="both", expand=True, padx=8, pady=8)
        style_listbox(self.lst_plans)
        self.lst_plans.bind("<<ListboxSelect>>", lambda e: self.on_plan_select())

        btns = ttk.Frame(left); btns.pack(fill="x", padx=8, pady=(0,8))
        ttk.Button(btns, text="New", command=self.plan_new, style="Colored.TButton").pack(side="left")
        ttk.Button(btns, text="Delete", command=self.plan_delete, style="Colored.TButton").pack(side="left", padx=6)
        ttk.Button(btns, text="Save Changes", command=self.plan_save, style="Colored.TButton").pack(side="left")

        right = ttk.LabelFrame(outer, text="Plan details")
        right.pack(side="left", fill="both", expand=True, padx=(12,0))
        form = ttk.Frame(right); form.pack(fill="both", expand=True, padx=10, pady=10)

        self._plans_selected: Optional[int] = None

        self.vpl_name = tk.StringVar()
        self.vpl_enabled = tk.BooleanVar(value=True)
        self.vpl_targets = tk.StringVar()
        self.vpl_preset = tk.StringVar()
        self.vpl_set = tk.StringVar(value="Default")

        self.vpl_restart_mode = tk.StringVar(value="none")
        self.vpl_rcon_cmd = tk.StringVar(value="#shutdown")
        self.vpl_nitrado_msg = tk.StringVar(value="AutomationZ restart")

        self.vpl_verify_mode = tk.StringVar(value="none")
        self.vpl_verify_path = tk.StringVar()
        self.vpl_verify_keys = tk.StringVar()

        self.vpl_rollback = tk.BooleanVar(value=True)

        self.vpl_sched_enabled = tk.BooleanVar(value=False)
        self.vpl_hour = tk.StringVar(value="0")
        self.vpl_min = tk.StringVar(value="0")
        self.vpl_days = {i: tk.BooleanVar(value=True) for i in range(7)}

        def bind_keep(widget):
            widget.bind("<FocusIn>", lambda _e: self._restore_sel(self.lst_plans, self._plans_selected))
            return widget

        r=0
        ttk.Label(form, text="Name").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vpl_name, width=56)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        bind_keep(ttk.Checkbutton(form, text="Enabled", variable=self.vpl_enabled)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Targets (profile names, comma-separated)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vpl_targets, width=56)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Preset folder").grid(row=r, column=0, sticky="w", pady=2)
        self.cmb_plan_preset = ttk.Combobox(form, textvariable=self.vpl_preset, state="readonly", width=53)
        self.cmb_plan_preset.grid(row=r, column=1, sticky="w", pady=2)
        bind_keep(self.cmb_plan_preset); r+=1

        ttk.Label(form, text="Mapping set").grid(row=r, column=0, sticky="w", pady=2)
        self.cmb_plan_set = ttk.Combobox(form, textvariable=self.vpl_set, state="readonly", width=53)
        self.cmb_plan_set.grid(row=r, column=1, sticky="w", pady=2)
        bind_keep(self.cmb_plan_set); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        ttk.Label(form, text="Restart mode").grid(row=r, column=0, sticky="w", pady=2)
        self.cmb_restart = ttk.Combobox(form, textvariable=self.vpl_restart_mode, state="readonly", width=20,
                                        values=["none","rcon","nitrado"])
        self.cmb_restart.grid(row=r, column=1, sticky="w", pady=2)
        bind_keep(self.cmb_restart); r+=1

        ttk.Label(form, text="RCON command (restart_mode=rcon)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vpl_rcon_cmd, width=56)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Nitrado restart message (restart_mode=nitrado)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vpl_nitrado_msg, width=56)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        ttk.Label(form, text="Verify mode (FTP only)").grid(row=r, column=0, sticky="w", pady=2)
        self.cmb_verify = ttk.Combobox(form, textvariable=self.vpl_verify_mode, state="readonly", width=20,
                                       values=["none","contains","not_contains"])
        self.cmb_verify.grid(row=r, column=1, sticky="w", pady=2)
        bind_keep(self.cmb_verify); r+=1

        ttk.Label(form, text="Verify remote path (FTP)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vpl_verify_path, width=56)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Label(form, text="Verify keywords (comma-separated)").grid(row=r, column=0, sticky="w", pady=2)
        bind_keep(ttk.Entry(form, textvariable=self.vpl_verify_keys, width=56)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        bind_keep(ttk.Checkbutton(form, text="Rollback on verify fail (v1 safe-mode: logs only)", variable=self.vpl_rollback)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        ttk.Separator(form, orient="horizontal").grid(row=r, column=0, columnspan=2, sticky="ew", pady=8); r+=1

        bind_keep(ttk.Checkbutton(form, text="Enable schedule (run automatically)", variable=self.vpl_sched_enabled)).grid(row=r, column=1, sticky="w", pady=2); r+=1

        hhmm = ttk.Frame(form); hhmm.grid(row=r, column=1, sticky="w", pady=2)
        ttk.Label(hhmm, text="Time:").pack(side="left")
        bind_keep(ttk.Entry(hhmm, textvariable=self.vpl_hour, width=4)).pack(side="left", padx=(6,2))
        ttk.Label(hhmm, text=":").pack(side="left")
        bind_keep(ttk.Entry(hhmm, textvariable=self.vpl_min, width=4)).pack(side="left", padx=(2,10))
        ttk.Label(hhmm, text="(24h)").pack(side="left")
        r+=1

        daysf = ttk.Frame(form); daysf.grid(row=r, column=1, sticky="w", pady=(4,2))
        ttk.Label(form, text="Days:").grid(row=r, column=0, sticky="w", pady=(4,2))
        for i in range(7):
            bind_keep(ttk.Checkbutton(daysf, text=weekday_name(i), variable=self.vpl_days[i])).pack(side="left", padx=3)
        r+=1

        ttk.Button(form, text="Open Presets Folder", command=lambda: self._open_safe(self.presets_dir), style="Colored.TButton").grid(row=r, column=1, sticky="w", pady=(10,2))

    def refresh_plans_ui(self):
        self.lst_plans.delete(0, "end")
        for p in self.plans:
            flag = "ON" if p.enabled else "OFF"
            sch = "AUTO" if (p.schedule_enabled and p.enabled) else "MANUAL"
            self.lst_plans.insert("end", f"[{flag}/{sch}] {p.name}")

        self.cmb_plan["values"] = [p.name for p in self.plans]
        if self.plans and self.cmb_plan.get() not in [p.name for p in self.plans]:
            self.cmb_plan.set(self.plans[0].name)

        presets = [p.name for p in sorted(self.presets_dir.iterdir()) if p.is_dir()] if self.presets_dir.exists() else []
        self.cmb_plan_preset["values"] = presets
        if presets and self.vpl_preset.get() not in presets:
            self.vpl_preset.set(presets[0])
        self.cmb_plan_set["values"] = [s.name for s in self.mapping_sets]
        if self.mapping_sets and self.vpl_set.get() not in [s.name for s in self.mapping_sets]:
            self.vpl_set.set(self.mapping_sets[0].name)

    def on_plan_select(self):
        idx = self._sel_index(self.lst_plans)
        self._plans_selected = idx
        if idx is None:
            return
        p = self.plans[idx]
        self.vpl_name.set(p.name)
        self.vpl_enabled.set(p.enabled)
        self.vpl_targets.set(p.targets_csv)
        self.vpl_preset.set(p.preset)
        self.vpl_set.set(p.mapping_set)

        self.vpl_restart_mode.set(p.restart_mode)
        self.vpl_rcon_cmd.set(p.rcon_command)
        self.vpl_nitrado_msg.set(p.nitrado_message)

        self.vpl_verify_mode.set(p.verify_mode)
        self.vpl_verify_path.set(p.verify_remote_path)
        self.vpl_verify_keys.set(p.verify_keywords_csv)
        self.vpl_rollback.set(p.rollback_on_fail)

        self.vpl_sched_enabled.set(p.schedule_enabled)
        self.vpl_hour.set(str(p.hour))
        self.vpl_min.set(str(p.minute))
        for i in range(7):
            self.vpl_days[i].set(i in p.days)

    def plan_new(self):
        presets = [p.name for p in sorted(self.presets_dir.iterdir()) if p.is_dir()] if self.presets_dir.exists() else []
        default_preset = presets[0] if presets else ""
        self.plans.append(Plan(
            name=f"Plan_{len(self.plans)+1}",
            enabled=True,
            targets_csv="",
            preset=default_preset,
            mapping_set="Default",
            restart_mode="none",
            rcon_command="#shutdown",
            nitrado_message="AutomationZ restart",
            verify_mode="none",
            verify_remote_path="",
            verify_keywords_csv="",
            rollback_on_fail=True,
            schedule_enabled=False,
            days=[0,1,2,3,4,5,6],
            hour=0,
            minute=0,
            last_run_key="",
        ))
        save_plans(self.plans)
        self.refresh_plans_ui()

    def plan_delete(self):
        idx = self._sel_index(self.lst_plans)
        if idx is None:
            return
        p = self.plans[idx]
        if not messagebox.askyesno("Delete", f"Delete plan '{p.name}'?"):
            return
        del self.plans[idx]
        save_plans(self.plans)
        self.refresh_plans_ui()

    def plan_save(self):
        idx = self._sel_index(self.lst_plans)
        if idx is None:
            messagebox.showwarning("No plan", "Select a plan first.")
            return
        try:
            hh = int((self.vpl_hour.get() or "0").strip())
            mm = int((self.vpl_min.get() or "0").strip())
            if hh < 0 or hh > 23 or mm < 0 or mm > 59:
                raise ValueError()
        except ValueError:
            messagebox.showerror("Invalid", "Hour must be 0-23 and minute 0-59.")
            return

        days = [i for i in range(7) if bool(self.vpl_days[i].get())] or [0,1,2,3,4,5,6]

        self.plans[idx] = Plan(
            name=self.vpl_name.get().strip() or self.plans[idx].name,
            enabled=bool(self.vpl_enabled.get()),
            targets_csv=self.vpl_targets.get().strip(),
            preset=self.vpl_preset.get().strip(),
            mapping_set=self.vpl_set.get().strip() or "Default",
            restart_mode=self.vpl_restart_mode.get().strip() or "none",
            rcon_command=self.vpl_rcon_cmd.get().strip() or "#shutdown",
            nitrado_message=self.vpl_nitrado_msg.get().strip() or "AutomationZ restart",
            verify_mode=self.vpl_verify_mode.get().strip() or "none",
            verify_remote_path=self.vpl_verify_path.get().strip(),
            verify_keywords_csv=self.vpl_verify_keys.get().strip(),
            rollback_on_fail=bool(self.vpl_rollback.get()),
            schedule_enabled=bool(self.vpl_sched_enabled.get()),
            days=days,
            hour=hh,
            minute=mm,
            last_run_key=self.plans[idx].last_run_key,
        )
        save_plans(self.plans)
        self.refresh_plans_ui()
        messagebox.showinfo("Saved", "Plan saved.")

    # ---------------- Settings ----------------

    def _build_settings(self):
        f = self.tab_settings
        outer = ttk.Frame(f); outer.pack(fill="both", expand=True, padx=12, pady=10)

        # App settings
        box1 = ttk.LabelFrame(outer, text="App")
        box1.pack(fill="x", padx=6, pady=6)

        self.vs_timeout = tk.StringVar(value=str((self.settings.get("app", {}) or {}).get("timeout_seconds", 25)))
        self.vs_tick = tk.StringVar(value=str((self.settings.get("app", {}) or {}).get("tick_seconds", 15)))
        self.vs_hosttype = tk.StringVar(value=str(self.settings.get("host_type","dedicated")))
        self.vs_presets_dir = tk.StringVar(value=str((self.settings.get("paths", {}) or {}).get("presets_dir","")))

        row = ttk.Frame(box1); row.pack(fill="x", padx=8, pady=6)
        ttk.Label(row, text="Timeout seconds").pack(side="left")
        ttk.Entry(row, textvariable=self.vs_timeout, width=6).pack(side="left", padx=(6,14))
        ttk.Label(row, text="Tick seconds").pack(side="left")
        ttk.Entry(row, textvariable=self.vs_tick, width=6).pack(side="left", padx=(6,14))
        ttk.Label(row, text="Host type").pack(side="left")
        ttk.Combobox(row, textvariable=self.vs_hosttype, state="readonly", width=12, values=["dedicated","nitrado"]).pack(side="left", padx=(6,0))

        row2 = ttk.Frame(box1); row2.pack(fill="x", padx=8, pady=(0,6))
        ttk.Label(row2, text="Presets folder override (optional)").pack(side="left")
        ttk.Entry(row2, textvariable=self.vs_presets_dir, width=60).pack(side="left", padx=(6,0))

        # Discord settings
        box2 = ttk.LabelFrame(outer, text="Discord Webhook")
        box2.pack(fill="x", padx=6, pady=6)

        d = self.settings.get("discord", {}) or {}
        self.vd_url = tk.StringVar(value=str(d.get("webhook_url","")))
        self.vd_user = tk.StringVar(value=str(d.get("username","AutomationZ")))
        self.vd_start = tk.BooleanVar(value=bool(d.get("notify_start", True)))
        self.vd_ok = tk.BooleanVar(value=bool(d.get("notify_success", True)))
        self.vd_fail = tk.BooleanVar(value=bool(d.get("notify_failure", True)))

        rowd = ttk.Frame(box2); rowd.pack(fill="x", padx=8, pady=6)
        ttk.Label(rowd, text="Webhook URL").pack(side="left")
        ttk.Entry(rowd, textvariable=self.vd_url, width=90).pack(side="left", padx=(6,0))

        rowd2 = ttk.Frame(box2); rowd2.pack(fill="x", padx=8, pady=(0,6))
        ttk.Label(rowd2, text="Username").pack(side="left")
        ttk.Entry(rowd2, textvariable=self.vd_user, width=30).pack(side="left", padx=(6,14))
        ttk.Checkbutton(rowd2, text="Notify start", variable=self.vd_start).pack(side="left")
        ttk.Checkbutton(rowd2, text="Notify success", variable=self.vd_ok).pack(side="left", padx=8)
        ttk.Checkbutton(rowd2, text="Notify failure", variable=self.vd_fail).pack(side="left")

        actions = ttk.Frame(outer); actions.pack(fill="x", padx=6, pady=10)
        ttk.Button(actions, text="Save Settings", command=self.settings_save, style="Colored.TButton").pack(side="left")
        ttk.Button(actions, text="Test Discord", command=self.discord_test, style="Colored.TButton").pack(side="left", padx=8)

        tips = tk.Text(outer, height=8, wrap="word")
        tips.pack(fill="both", expand=True, padx=6, pady=(0,6))
        style_text_widget(tips)
        tips.insert("1.0",
            "Tips:\n"
            "- If you run on Nitrado (no RCON password shown), use FTP upload only, and restart via Nitrado API.\n"
            "- On Nitrado find Battleye BEServer.cfg, it contains your rcon password, Ip and port if using battleye\n"
            "- Local mode is for people hosting at home: mappings are applied into a local server folder.\n"
            "- Presets folder override lets you store presets anywhere (e.g. a synced folder).\n"
        )
        tips.configure(state="disabled")

    def settings_save(self):
        try:
            timeout = int((self.vs_timeout.get() or "25").strip())
            tick = int((self.vs_tick.get() or "15").strip())
        except ValueError:
            messagebox.showerror("Invalid", "Timeout/Tick must be numbers.")
            return

        self.settings.setdefault("app", {})
        self.settings["app"]["timeout_seconds"] = max(5, timeout)
        self.settings["app"]["tick_seconds"] = max(5, tick)
        self.settings["host_type"] = (self.vs_hosttype.get() or "dedicated").strip()

        self.settings.setdefault("paths", {})
        self.settings["paths"]["presets_dir"] = (self.vs_presets_dir.get() or "").strip()

        self.settings.setdefault("discord", {})
        self.settings["discord"]["webhook_url"] = (self.vd_url.get() or "").strip()
        self.settings["discord"]["username"] = (self.vd_user.get() or "AutomationZ").strip()
        self.settings["discord"]["notify_start"] = bool(self.vd_start.get())
        self.settings["discord"]["notify_success"] = bool(self.vd_ok.get())
        self.settings["discord"]["notify_failure"] = bool(self.vd_fail.get())

        save_json(SETTINGS_PATH, self.settings)

        # apply runtime
        self.timeout = int((self.settings.get("app", {}) or {}).get("timeout_seconds", 25))
        self.tick_seconds = int((self.settings.get("app", {}) or {}).get("tick_seconds", 15))
        self.presets_dir = presets_dir_from_settings(self.settings)
        self.orch.settings = self.settings
        self.orch.discord.settings = self.settings

        self.refresh_presets_ui()
        self.refresh_plans_ui()
        messagebox.showinfo("Saved", "Settings saved.")

    def discord_test(self):
        try:
            self.settings_save()
            self.orch.discord.post("✅ AutomationZ Admin Orchestrator: Discord webhook test message.")
            messagebox.showinfo("Sent", "Test message sent (if webhook URL is valid).")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    # ---------------- Help ----------------

    def _build_help(self):
        t = tk.Text(self.tab_help, wrap="word")
        t.pack(fill="both", expand=True, padx=12, pady=12)
        style_text_widget(t)
        t.insert("1.0",
            f"{APP_NAME}\n"
            "Created by Danny van den Brande\n\n"
            "AutomationZ Server Backup Scheduler is free and open-source software.\n\n"
            "If this tool helps you automate server tasks, save time,\n"
            "or manage multiple servers more easily,\n"
            "consider supporting development with a donation.\n\n"
            "Donations are optional, but appreciated and help\n"
            "support ongoing development and improvements.\n\n"
            "Support link:\n"
            "https://ko-fi.com/dannyvandenbrande\n\n"
            "What this does\n"
            "- Upload one preset (folder of files) to one or multiple servers via FTP/FTPS.\n"
            "- OR apply the same mappings to a local server folder (Local mode).\n"
            "- Optionally trigger a restart after upload using:\n"
            "  * BattlEye RCON (UDP)\n"
            "  * Nitrado API restart (requires Service ID + Lifelong token)\n"
            "- Optional verification step (FTP only): download a remote file and check keywords.\n"
            "- Scheduler: run plans automatically on chosen days + time.\n\n"
            "Quick start\n"
            "1) Settings tab: add Discord webhook (optional) + presets folder (optional).\n"
            "2) Profiles tab: create a profile (FTP or Local mode).\n"
            "3) Mappings tab: create mappings (preset file -> destination path).\n"
            "4) Mapping Sets tab: create sets of mappings.\n"
            "5) Presets: create a folder in presets/ and put your files inside.\n"
            "6) Plans tab: pick targets + preset + mapping set + restart mode.\n"
            "7) Dashboard: run a plan now, or start the scheduler.\n"
        )
        t.configure(state="disabled")


def main():
    for p in [CONFIG_DIR, LOGS_DIR, BACKUPS_DIR, DEFAULT_PRESETS_DIR]:
        p.mkdir(parents=True, exist_ok=True)
    App().mainloop()

if __name__ == "__main__":
    main()
