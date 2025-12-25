#!/usr/bin/env python3
from __future__ import annotations

import json
import time
import socket
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception as e:
    raise SystemExit(f"Tkinter is required. Error: {e}")

# -----------------------------
# AutomationZ Dark Theme (fixed)
# -----------------------------
C_BG = "#333333"
C_PANEL = "#363636"
C_TEXT = "#e6e6e6"
C_MUTED = "#b8b8b8"
C_ACCENT = "#4CAF50"
C_WARN = "#ffb74d"
C_BAD = "#ef5350"

def apply_dark_theme(root: tk.Tk) -> ttk.Style:
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass

    root.configure(bg=C_BG)
    style.configure(".", background=C_BG, foreground=C_TEXT, fieldbackground=C_PANEL)
    style.configure("TFrame", background=C_BG)
    style.configure("TLabelframe", background=C_BG, foreground=C_TEXT)
    style.configure("TLabelframe.Label", background=C_BG, foreground=C_TEXT)
    style.configure("TLabel", background=C_BG, foreground=C_TEXT)
    style.configure("TSeparator", background=C_BG)

    style.configure("TEntry", fieldbackground=C_PANEL, foreground=C_TEXT, insertcolor=C_TEXT)
    style.configure("TCombobox", fieldbackground=C_PANEL, foreground=C_TEXT)
    style.map("TCombobox", fieldbackground=[("readonly", C_PANEL)])

    style.configure("TButton", background=C_PANEL, foreground=C_TEXT, borderwidth=0, padding=(10, 6))
    style.map("TButton",
              background=[("active", "#404040"), ("pressed", "#2a2a2a")],
              foreground=[("disabled", C_MUTED)])

    style.configure("Colored.TButton", background=C_ACCENT, foreground="#ffffff", borderwidth=0, padding=(10, 6))
    style.map("Colored.TButton",
              background=[("active", "#43A047"), ("pressed", "#2e7d32")],
              foreground=[("disabled", "#cfcfcf")])


    # Notebook tab text visibility fix (Windows/Linux)
    style.configure(
        "TNotebook.Tab",
        foreground="#363636",
        padding=(12, 6)
    )
    style.map(
        "TNotebook.Tab",
        foreground=[("selected", "#363636")]
    )

    return style

def style_listbox(lb: tk.Listbox) -> None:
    lb.configure(
        bg=C_PANEL,
        fg=C_TEXT,
        selectbackground="#1f3b2b",
        selectforeground=C_TEXT,
        highlightbackground="#1f1f1f",
        highlightcolor=C_ACCENT,
        relief="flat",
        bd=0,
    )

BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "restart_loop_config.json"
HELP_TEXT = "Restart Loop Guard works locally.\n\nIt guards restart/start attempts (not crashes).\nIf restart attempts originate from another machine, run the tool there.\n\nTypical use:\n- Your restart script calls the guard before attempting a restart.\n- If the guard locks, your script should stop restarting until an admin unlocks.\n"

def _now_ts() -> int:
    return int(time.time())

def _iso(ts: Optional[int] = None) -> str:
    if ts is None:
        return datetime.now().isoformat(timespec="seconds")
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")

def load_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

def save_json(path: Path, data: Any) -> None:
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def append_log(log_file: Path, msg: str) -> None:
    with open(log_file, "a", encoding="utf-8") as f:
        f.write(f"[{_iso()}] {msg}\n")

def tail_file(path: Path, n: int) -> str:
    if n <= 0 or not path.exists():
        return ""
    try:
        lines = path.read_text(encoding="utf-8", errors="ignore").splitlines()
        return "\n".join(lines[-n:])
    except Exception:
        return ""

def post_discord(webhook_url: str, content: str) -> None:
    if not webhook_url:
        return
    payload = json.dumps({"content": content}).encode("utf-8")
    req = urllib.request.Request(
        webhook_url,
        data=payload,
        headers={"Content-Type": "application/json", "User-Agent": "AutomationZ-RestartLoopGuard-UI/1.1"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        resp.read()

@dataclass
class Status:
    state: str
    message: str
    attempt_count: int
    max_attempts: int
    window_seconds: int
    timestamps: List[int]

def compute_status(cfg: Dict[str, Any], history: List[int], now: int, locked: bool) -> Status:
    max_attempts = int(cfg.get("max_attempts", 3))
    window = int(cfg.get("time_window_seconds", 300))

    windowed = [int(t) for t in history if now - int(t) <= window]
    count = len(windowed)

    if locked:
        return Status("LOCKED", "Restart loop locked. Manual unlock required.", count, max_attempts, window, windowed)

    if count >= max(1, max_attempts - 1):
        return Status("WARNING", f"Near threshold: {count}/{max_attempts} within {window}s.", count, max_attempts, window, windowed)

    return Status("OK", f"Normal: {count}/{max_attempts} within {window}s.", count, max_attempts, window, windowed)

def make_incident(cfg: Dict[str, Any], status: Status, now: int) -> Dict[str, Any]:
    extra = (cfg.get("notify", {}) or {}).get("extra_context", {}) if isinstance(cfg.get("notify", {}), dict) else {}
    return {
        "version": "1.1-ui",
        "time": _iso(now),
        "timestamp": now,
        "state": status.state,
        "message": status.message,
        "attempt_count": status.attempt_count,
        "max_attempts": status.max_attempts,
        "window_seconds": status.window_seconds,
        "attempt_timestamps": status.timestamps,
        "host": {"hostname": socket.gethostname(), "fqdn": socket.getfqdn()},
        "automationz": extra,
    }

class App(tk.Tk):
    def __init__(self) -> None:
        super().__init__()
        apply_dark_theme(self)
        self.title("AutomationZ Restart Loop Guard")
        self.geometry("900x590")
        self.minsize(900, 590)

        self.cfg: Dict[str, Any] = {}
        self.state_file: Path
        self.lock_file: Path
        self.incident_file: Path
        self.log_file: Path

        self._build_ui()
        self._load_cfg(silent=True)
        self.refresh_status(record=False)

    def _build_ui(self) -> None:
        outer = ttk.Frame(self, padding=14)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="AutomationZ Restart Loop Guard", font=("Segoe UI", 16, "bold")).pack(side="left")
        self.status_badge = tk.Label(header, text="—", bg=C_PANEL, fg=C_TEXT, padx=10, pady=6)
        self.status_badge.pack(side="right")

        banner = tk.Label(
            outer,
            text="⚠️ Local tool: guards restart/start attempts on this machine only.",
            bg=C_BG,
            fg=C_WARN,
            anchor="w",
            padx=2,
        )
        banner.pack(fill="x", pady=(6, 10))

        nb = ttk.Notebook(outer)
        nb.pack(fill="both", expand=True)
        self.tab_main = ttk.Frame(nb)
        self.tab_help = ttk.Frame(nb)
        nb.add(self.tab_main, text="Dashboard")
        nb.add(self.tab_help, text="Help")

        help_box = ttk.LabelFrame(self.tab_help, text="How it works", padding=10)
        help_box.pack(fill="both", expand=True, padx=10, pady=10)
        txt = tk.Text(help_box, bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                      relief="flat", bd=0, highlightbackground="#1f1f1f", highlightcolor=C_ACCENT, wrap="word")
        txt.pack(fill="both", expand=True)
        txt.insert("1.0", HELP_TEXT)
        txt.configure(state="disabled")

        top = ttk.Frame(self.tab_main, padding=10)
        top.pack(fill="both", expand=True)
        mid = ttk.Frame(top)
        mid.pack(fill="both", expand=True)

        left = ttk.Frame(mid)
        left.pack(side="left", fill="y", padx=(0, 10))

        cfg_box = ttk.LabelFrame(left, text="Config", padding=10)
        cfg_box.pack(fill="x")

        self.var_max = tk.StringVar()
        self.var_window = tk.StringVar()
        self.var_backoff = tk.StringVar()
        self.var_notify_enabled = tk.BooleanVar()
        self.var_webhook = tk.StringVar()

        row = ttk.Frame(cfg_box); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Max attempts").pack(side="left")
        ttk.Entry(row, textvariable=self.var_max, width=10).pack(side="right")

        row = ttk.Frame(cfg_box); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Window (sec)").pack(side="left")
        ttk.Entry(row, textvariable=self.var_window, width=10).pack(side="right")

        row = ttk.Frame(cfg_box); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Backoff list").pack(side="left")
        ttk.Entry(row, textvariable=self.var_backoff, width=28).pack(side="right")

        ttk.Separator(cfg_box).pack(fill="x", pady=(10, 8))

        row = ttk.Frame(cfg_box); row.pack(fill="x", pady=4)
        ttk.Checkbutton(row, text="Discord notify", variable=self.var_notify_enabled).pack(side="left")

        row = ttk.Frame(cfg_box); row.pack(fill="x", pady=4)
        ttk.Label(row, text="Webhook URL").pack(anchor="w")
        ttk.Entry(row, textvariable=self.var_webhook, width=34).pack(fill="x", pady=(2, 0))

        btns = ttk.Frame(left)
        btns.pack(fill="x", pady=(10, 0))
        ttk.Button(btns, text="Save Config", style="Colored.TButton", command=self.save_cfg).pack(fill="x", pady=4)
        ttk.Button(btns, text="Reload Config", command=self._load_cfg).pack(fill="x", pady=4)
        ttk.Button(btns, text="Test Discord", command=self.test_discord).pack(fill="x", pady=4)

        right = ttk.Frame(mid)
        right.pack(side="left", fill="both", expand=True)

        status_box = ttk.LabelFrame(right, text="Status", padding=10)
        status_box.pack(fill="x")

        self.lbl_status = ttk.Label(status_box, text="—", font=("Segoe UI", 11, "bold"))
        self.lbl_status.pack(anchor="w")
        self.lbl_counts = ttk.Label(status_box, text="—", foreground=C_MUTED)
        self.lbl_counts.pack(anchor="w", pady=(4, 0))

        actions = ttk.Frame(status_box)
        actions.pack(fill="x", pady=(10, 0))
        ttk.Button(actions, text="Record Start Attempt", style="Colored.TButton",
                   command=lambda: self.refresh_status(record=True)).pack(side="left")
        ttk.Button(actions, text="Analyze Only",
                   command=lambda: self.refresh_status(record=False)).pack(side="left", padx=8)
        ttk.Button(actions, text="Unlock", command=self.unlock).pack(side="right")
        ttk.Button(actions, text="Clear History", command=self.clear_history).pack(side="right", padx=8)

        lower = ttk.Frame(right)
        lower.pack(fill="both", expand=True, pady=(10, 0))

        history_box = ttk.LabelFrame(lower, text="Attempt History (in window)", padding=10)
        history_box.pack(side="left", fill="both", expand=True, padx=(0, 10))
        self.lb = tk.Listbox(history_box, height=12)
        style_listbox(self.lb)
        self.lb.pack(fill="both", expand=True)

        log_box = ttk.LabelFrame(lower, text="Log (tail)", padding=10)
        log_box.pack(side="left", fill="both", expand=True)
        self.txt_log = tk.Text(log_box, height=12, bg=C_PANEL, fg=C_TEXT, insertbackground=C_TEXT,
                               relief="flat", bd=0, highlightbackground="#1f1f1f", highlightcolor=C_ACCENT)
        self.txt_log.pack(fill="both", expand=True)

    def _load_cfg(self, silent: bool = False) -> None:
        self.cfg = load_json(CONFIG_FILE, default={})
        if not self.cfg:
            self.cfg = {
  "max_attempts": 3,
  "time_window_seconds": 300,
  "backoff_seconds": [
    0,
    60,
    180,
    300
  ],
  "state_file": "attempt_history.json",
  "lock_file": "restart_loop.lock",
  "incident_file": "incident_report.json",
  "log_file": "restart_loop.log",
  "notify": {
    "enabled": false,
    "discord_webhook_url": "",
    "include_last_lines": 40,
    "extra_context": {
      "server_name": "THE LONG HUNT",
      "host": "",
      "notes": ""
    }
  }
}
            save_json(CONFIG_FILE, self.cfg)

        self.state_file = BASE_DIR / self.cfg.get("state_file", "attempt_history.json")
        self.lock_file = BASE_DIR / self.cfg.get("lock_file", "restart_loop.lock")
        self.incident_file = BASE_DIR / self.cfg.get("incident_file", "incident_report.json")
        self.log_file = BASE_DIR / self.cfg.get("log_file", "restart_loop.log")

        self.var_max.set(str(self.cfg.get("max_attempts", 3)))
        self.var_window.set(str(self.cfg.get("time_window_seconds", 300)))
        self.var_backoff.set(",".join(str(x) for x in (self.cfg.get("backoff_seconds", [0, 60, 180, 300]) or [])))

        notify = self.cfg.get("notify", {}) if isinstance(self.cfg.get("notify", {}), dict) else {}
        self.var_notify_enabled.set(bool(notify.get("enabled", False)))
        self.var_webhook.set(str(notify.get("discord_webhook_url", "")))

        if not silent:
            messagebox.showinfo("Config loaded", "Config reloaded successfully.")

    def save_cfg(self) -> None:
        try:
            max_a = int(self.var_max.get().strip())
            win_s = int(self.var_window.get().strip())
            backoff = [int(x.strip()) for x in self.var_backoff.get().split(",") if x.strip() != ""]
            notify_enabled = bool(self.var_notify_enabled.get())
            webhook = self.var_webhook.get().strip()

            self.cfg["max_attempts"] = max_a
            self.cfg["time_window_seconds"] = win_s
            self.cfg["backoff_seconds"] = backoff

            if "notify" not in self.cfg or not isinstance(self.cfg["notify"], dict):
                self.cfg["notify"] = {}
            self.cfg["notify"]["enabled"] = notify_enabled
            self.cfg["notify"]["discord_webhook_url"] = webhook

            save_json(CONFIG_FILE, self.cfg)
            messagebox.showinfo("Saved", "Config saved.")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def refresh_status(self, record: bool) -> None:
        now = _now_ts()
        history = load_json(self.state_file, default=[])
        if not isinstance(history, list):
            history = []

        locked = self.lock_file.exists()

        if record and not locked:
            history.append(now)
            save_json(self.state_file, history)
            append_log(self.log_file, "Recorded start attempt (UI).")

        status = compute_status(self.cfg, history, now, locked)
        save_json(self.state_file, status.timestamps)

        max_attempts = int(self.cfg.get("max_attempts", 3))
        if record and (len(status.timestamps) >= max_attempts) and not self.lock_file.exists():
            self.lock_file.touch()
            status = compute_status(self.cfg, status.timestamps, now, True)
            append_log(self.log_file, f"LOCKED (threshold reached). {len(status.timestamps)} in window.")
            save_json(self.incident_file, make_incident(self.cfg, status, now))
            self._maybe_notify(status)

        self._set_badge(status.state)
        self.lbl_status.configure(text=status.message)
        self.lbl_counts.configure(text=f"Attempts in window: {status.attempt_count} | Threshold: {status.max_attempts} | Window: {status.window_seconds}s")

        self.lb.delete(0, tk.END)
        for ts in reversed(status.timestamps):
            self.lb.insert(tk.END, f"{_iso(ts)}  ({ts})")

        self._refresh_log()

    def _refresh_log(self) -> None:
        tail = tail_file(self.log_file, 80)
        self.txt_log.delete("1.0", tk.END)
        self.txt_log.insert("1.0", tail)

    def _set_badge(self, state: str) -> None:
        if state == "OK":
            bg, fg, txt = C_ACCENT, "#ffffff", "OK"
        elif state == "WARNING":
            bg, fg, txt = C_WARN, "#111111", "WARNING"
        else:
            bg, fg, txt = C_BAD, "#111111", "LOCKED"
        self.status_badge.configure(text=txt, bg=bg, fg=fg)

    def unlock(self) -> None:
        if not self.lock_file.exists():
            messagebox.showinfo("Unlock", "No lock file present.")
            return
        try:
            self.lock_file.unlink()
            append_log(self.log_file, "Lock removed (UI).")
            messagebox.showinfo("Unlocked", "Lock removed.")
            self.refresh_status(record=False)
        except Exception as e:
            messagebox.showerror("Unlock failed", str(e))

    def clear_history(self) -> None:
        if not messagebox.askyesno("Clear history", "Clear attempt history?"):
            return
        try:
            if self.state_file.exists():
                self.state_file.unlink()
            append_log(self.log_file, "History cleared (UI).")
            messagebox.showinfo("Cleared", "Attempt history cleared.")
            self.refresh_status(record=False)
        except Exception as e:
            messagebox.showerror("Clear failed", str(e))

    def _maybe_notify(self, status: Status) -> None:
        notify_cfg = self.cfg.get("notify", {}) if isinstance(self.cfg.get("notify", {}), dict) else {}
        if not notify_cfg.get("enabled"):
            return
        webhook = str(notify_cfg.get("discord_webhook_url", "")).strip()
        if not webhook:
            append_log(self.log_file, "Notify enabled but webhook empty.")
            return

        last_lines = int(notify_cfg.get("include_last_lines", 40))
        extra = notify_cfg.get("extra_context", {}) if isinstance(notify_cfg.get("extra_context", {}), dict) else {}

        msg = (
            f"❌ **Restart loop LOCKED**\n"
            f"- **Reason:** {status.message}\n"
            f"- **Attempts in window:** {status.attempt_count}\n"
            f"- **Window:** {status.window_seconds}s\n"
            f"- **Host:** {socket.gethostname()}\n"
        )
        if extra.get("server_name"):
            msg += f"- **Server:** {extra.get('server_name')}\n"
        if extra.get("host"):
            msg += f"- **Server Host:** {extra.get('host')}\n"
        if extra.get("notes"):
            msg += f"- **Notes:** {extra.get('notes')}\n"

        snippet = tail_file(self.log_file, last_lines)
        if snippet:
            msg += "\n**Last log lines:**\n```text\n" + snippet[-1500:] + "\n```"

        try:
            post_discord(webhook, msg)
            append_log(self.log_file, "Notification sent (Discord).")
        except Exception as e:
            append_log(self.log_file, f"Notification failed: {e!r}")

    def test_discord(self) -> None:
        if not bool(self.var_notify_enabled.get()):
            messagebox.showinfo("Discord", "Enable Discord notify first (checkbox).")
            return
        webhook = self.var_webhook.get().strip()
        if not webhook:
            messagebox.showerror("Discord", "Webhook URL is empty.")
            return
        try:
            post_discord(webhook, f"✅ Restart Loop Guard UI test from **{socket.gethostname()}** at {_iso()}.")
            messagebox.showinfo("Discord", "Test message sent.")
        except Exception as e:
            messagebox.showerror("Discord", str(e))

if __name__ == "__main__":
    App().mainloop()
