#!/usr/bin/env python3
from __future__ import annotations

import os, json, time, ftplib, threading, socket, struct, zlib, urllib.request, queue
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception as e:
    raise SystemExit("Tkinter is required. Error: %s" % e)

APP_NAME = "AutomationZ Restart Companion"
APP_VERSION = "0.2.7"

# AutomationZ dark/green
C_BG="#333333"; C_PANEL="#363636"; C_TEXT="#e6e6e6"; C_MUTED="#b8b8b8"; C_ACCENT="#4CAF50"; C_WARN="#ffb74d"; C_BAD="#ef5350"
CONFIG_NAME="config.json"

def now_ts(): return time.strftime("%Y-%m-%d %H:%M:%S")
def safe_int(v, d):
    try: return int(str(v).strip())
    except: return d
def safe_bool(v, d=False):
    if isinstance(v,bool): return v
    if v is None: return d
    s=str(v).strip().lower()
    if s in ("1","true","yes","y","on"): return True
    if s in ("0","false","no","n","off"): return False
    return d
def human_secs(secs:int)->str:
    m,s=divmod(max(0,int(secs)),60); h,m=divmod(m,60)
    return f"{h:02d}:{m:02d}:{s:02d}" if h else f"{m:02d}:{s:02d}"

def apply_dark_theme(root: tk.Tk):
    root.configure(bg=C_BG)
    style = ttk.Style(root)
    try: style.theme_use("clam")
    except: pass
    style.configure(".", background=C_BG, foreground=C_TEXT, fieldbackground=C_PANEL)
    style.configure("TFrame", background=C_BG)
    style.configure("Panel.TFrame", background=C_PANEL)
    style.configure("TLabel", background=C_BG, foreground=C_TEXT)
    style.configure("Muted.TLabel", background=C_BG, foreground=C_MUTED)
    style.configure("TEntry", fieldbackground=C_PANEL, foreground=C_TEXT)
    style.configure("TCombobox", fieldbackground=C_PANEL, foreground=C_TEXT)
    style.configure("TLabelframe", background=C_BG, foreground=C_TEXT)
    style.configure("TLabelframe.Label", background=C_BG, foreground=C_TEXT)
    style.configure("TButton", background=C_PANEL, foreground=C_TEXT, borderwidth=1, focusthickness=1)
    style.map("TButton", background=[("active","#3f3f3f")], foreground=[("disabled",C_MUTED)])
    style.configure("Colored.TButton", background=C_ACCENT, foreground="white")
    style.map("Colored.TButton", background=[("active","#45a049")])
    style.configure("Bad.TButton", background=C_BAD, foreground="white")
    style.map("Bad.TButton", background=[("active","#d94b4b")])
    style.configure("Treeview", background=C_PANEL, fieldbackground=C_PANEL, foreground=C_TEXT, rowheight=24, borderwidth=0)
    style.map("Treeview", background=[("selected","#1f3b2b")], foreground=[("selected",C_TEXT)])

@dataclass
class FTPConfig:
    host:str=""; user:str=""; password:str=""; port:int=21; tls:int=0; timeout:int=12

@dataclass
class RCONConfig:
    host:str=""; port:int=2305; password:str=""; command:str="#shutdown"; timeout:int=6; retries:int=3

@dataclass
class DiscordConfig:
    enabled:bool=False; webhook_url:str=""

@dataclass
class Target:
    name:str="My Server"
    mode:str="ftp"  # ftp|local
    local_path:str=""
    ftp:FTPConfig=field(default_factory=FTPConfig)
    remote_path:str="/"
    watch_kind:str="newest_mtime"  # newest_mtime|marker_file
    marker_file:str="automationz_last_deploy.txt"
    include_exts:str=".pbo,.txt,.json"
    action:str="notify"  # notify|local_command|rcon_command
    command:str=""
    rcon:RCONConfig=field(default_factory=RCONConfig)
    discord:DiscordConfig=field(default_factory=DiscordConfig)
    delay_minutes:int=10

def cfg_path()->Path:
    return Path(__file__).resolve().parent/CONFIG_NAME

def default_config()->Dict[str,Any]:
    return {"app":{"poll_seconds":30,"auto_start":False},"targets":[asdict(Target())]}

def load_config()->Dict[str,Any]:
    p=cfg_path()
    if not p.exists():
        cfg=default_config()
        p.write_text(json.dumps(cfg,indent=2),encoding="utf-8")
        return cfg
    try:
        cfg=json.loads(p.read_text(encoding="utf-8"))
    except:
        cfg=default_config()
        p.write_text(json.dumps(cfg,indent=2),encoding="utf-8")
        return cfg
    cfg.setdefault("app",{})
    cfg["app"].setdefault("poll_seconds",30)
    cfg["app"].setdefault("auto_start",False)
    for t in cfg.get("targets",[]) or []:
        t.setdefault("ftp", asdict(FTPConfig()))
        t.setdefault("rcon", asdict(RCONConfig()))
        t.setdefault("discord", asdict(DiscordConfig()))
        t.setdefault("action","notify")
        t.setdefault("command","")
        t.setdefault("delay_minutes",10)
    return cfg

def save_config(cfg:Dict[str,Any])->None:
    cfg_path().write_text(json.dumps(cfg,indent=2),encoding="utf-8")

# FTP helpers
def ftp_connect(ftp_cfg: FTPConfig):
    if ftp_cfg.tls:
        ftp=ftplib.FTP_TLS()
        ftp.connect(ftp_cfg.host,int(ftp_cfg.port or 21),timeout=int(ftp_cfg.timeout or 12))
        ftp.login(ftp_cfg.user,ftp_cfg.password); ftp.prot_p(); return ftp
    ftp=ftplib.FTP()
    ftp.connect(ftp_cfg.host,int(ftp_cfg.port or 21),timeout=int(ftp_cfg.timeout or 12))
    ftp.login(ftp_cfg.user,ftp_cfg.password); return ftp

def ftp_try_mdtm(ftp: ftplib.FTP, path: str)->Optional[int]:
    try:
        resp=ftp.sendcmd(f"MDTM {path}")
        parts=resp.split()
        if len(parts)>=2 and parts[0]=="213":
            dt=parts[1].strip()
            import datetime
            y=int(dt[0:4]); mo=int(dt[4:6]); d=int(dt[6:8]); hh=int(dt[8:10]); mm=int(dt[10:12]); ss=int(dt[12:14])
            return int(datetime.datetime(y,mo,d,hh,mm,ss).timestamp())
    except: return None
    return None

def newest_mtime_local(root:Path, exts:List[str])->Optional[int]:
    newest=None
    for dirpath,_,filenames in os.walk(root):
        for fn in filenames:
            if exts and not any(fn.lower().endswith(e) for e in exts): continue
            p=Path(dirpath)/fn
            try:
                mt=int(p.stat().st_mtime)
                newest=mt if newest is None or mt>newest else newest
            except: pass
    return newest

def marker_mtime_local(root:Path, marker_file:str)->Optional[int]:
    p=root/marker_file
    if not p.exists(): return None
    try: return int(p.stat().st_mtime)
    except: return None

def newest_mtime_ftp(ftp_cfg:FTPConfig, remote_root:str, exts:List[str])->Optional[int]:
    newest=None; ftp=None
    try:
        ftp=ftp_connect(ftp_cfg); ftp.cwd(remote_root)
        items=[]; ftp.retrlines("NLST", items.append)
        for name in items:
            if exts and not any(name.lower().endswith(e) for e in exts): continue
            mt=ftp_try_mdtm(ftp,name)
            if mt is None: continue
            newest=mt if newest is None or mt>newest else newest
    finally:
        try:
            if ftp: ftp.quit()
        except: pass
    return newest

def marker_mtime_ftp(ftp_cfg:FTPConfig, remote_root:str, marker_file:str)->Optional[int]:
    ftp=None
    try:
        ftp=ftp_connect(ftp_cfg); ftp.cwd(remote_root)
        return ftp_try_mdtm(ftp, marker_file)
    finally:
        try:
            if ftp: ftp.quit()
        except: pass

# Discord
def discord_send(webhook_url:str, content:str, timeout:int=8)->None:
    url=(webhook_url or "").strip()
    if not url: return
    payload=json.dumps({"content":content}).encode("utf-8")
    req=urllib.request.Request(url,data=payload,headers={"Content-Type":"application/json","User-Agent":"AutomationZ-RestartDelayCompanion"},method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        resp.read()

# BattlEye RCON UDP
# ------------------------- BE RCON (UDP) -------------------------

class BERcon:
    """
    Minimal BattlEye RCon client (UDP).
    This is the SAME implementation used by AutomationZ Admin Orchestrator (known working).
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

def be_rcon_shutdown(host: str, port: int, password: str, command: str, timeout: int = 6, retries: int = 3) -> str:
    # retries is accepted for compatibility with older call sites (BattlEye is UDP).
    r = BERcon(host, int(port), password, timeout=float(timeout))
    r.connect()
    try:
        return r.command(command or "#shutdown")
    finally:
        r.close()



class MonitorThread(threading.Thread):
    def __init__(self, app:"App"):
        super().__init__(daemon=True)
        self.app=app
        self.stop_flag=threading.Event()
    def stop(self): self.stop_flag.set()
    def run(self):
        while not self.stop_flag.is_set():
            self.app.poll_all_targets()
            for _ in range(10):
                if self.stop_flag.is_set(): break
                self.app.tick_countdowns()
                time.sleep(1)

class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1100x840"); self.minsize(980,720)
        apply_dark_theme(self)

        self.ui_q: "queue.Queue[Tuple[str, Any]]" = queue.Queue()

        self.cfg=load_config()
        self.poll_seconds=safe_int(self.cfg.get("app",{}).get("poll_seconds",30),30)
        self.auto_start=safe_bool(self.cfg.get("app",{}).get("auto_start",False),False)

        self.last_seen:Dict[str,Optional[int]]={}
        self.pending_until:Dict[str,Optional[float]]={}
        self.monitor:Optional[MonitorThread]=None
        self._last_poll=0.0

        self._build_ui()
        self._load_targets()
        self._q_status("Idle. Add a target and click Start Monitoring.")
        self.protocol("WM_DELETE_WINDOW", self._on_close)

        self.after(60, self._drain_ui)
        if self.auto_start:
            self.after(400, self._auto_start)

    # thread-safe UI queue
    def _q_log(self, msg:str, level:str="INFO"): self.ui_q.put(("log",(msg,level)))
    def _q_status(self, msg:str): self.ui_q.put(("status",msg))
    def _q_refresh(self): self.ui_q.put(("refresh",None))

    def _drain_ui(self):
        try:
            while True:
                kind,p=self.ui_q.get_nowait()
                if kind=="log":
                    msg,level=p
                    line=f"[{now_ts()}] [{level}] {msg}\n"
                    self.txt.configure(state="normal")
                    self.txt.insert("end", line)
                    self.txt.see("end")
                    self.txt.configure(state="disabled")
                elif kind=="status":
                    self.status_var.set(str(p))
                elif kind=="refresh":
                    self._refresh_tree_state()
        except queue.Empty:
            pass
        self.after(80, self._drain_ui)

    def _auto_start(self):
        try:
            if not (self.monitor and self.monitor.is_alive()):
                self._toggle()
        except Exception as e:
            self._q_log(f"Auto-start failed: {e}","WARN")

    def _build_ui(self):
        root=ttk.Frame(self); root.pack(fill="both",expand=True,padx=10,pady=10)
        left=ttk.Frame(root,style="Panel.TFrame"); left.pack(side="left",fill="y",padx=(0,10))
        right=ttk.Frame(root); right.pack(side="right",fill="both",expand=True)

        ttk.Label(left,text="Targets",font=("Segoe UI",11,"bold")).pack(anchor="w",padx=10,pady=(10,4))
        cols=("mode","delay","state")
        self.tree=ttk.Treeview(left,columns=cols,show="headings",height=18)
        for c,t,w,a in [("mode","Mode",60,"center"),("delay","Delay",60,"center"),("state","State",190,"w")]:
            self.tree.heading(c,text=t); self.tree.column(c,width=w,anchor=a)
        self.tree.pack(fill="y",expand=False,padx=10,pady=(0,10))
        self.tree.bind("<<TreeviewSelect>>", self._on_select)

        btns=ttk.Frame(left,style="Panel.TFrame"); btns.pack(fill="x",padx=10,pady=(0,10))
        ttk.Button(btns,text="Add",command=self._add,style="Colored.TButton").pack(fill="x",pady=(0,6))
        ttk.Button(btns,text="Delete",command=self._delete,style="Bad.TButton").pack(fill="x",pady=(0,6))
        ttk.Button(btns,text="Save Config",command=self._save).pack(fill="x")

        credit = ttk.Frame(left, style="Panel.TFrame")
        credit.pack(fill="x", padx=10, pady=(6, 10))

        ttk.Label(
            credit,
            text="By Danny van den Brande",
            style="Muted.TLabel",
            anchor="center"
        ).pack(fill="x")

        def _open(url):
            import webbrowser
            webbrowser.open(url)

        kofi = ttk.Label(
            credit,
            text="https://ko-fi.com/dannyvandenbrande",
            style="Muted.TLabel",
            anchor="center",
            cursor="hand2"
        )
        kofi.pack(fill="x")
        kofi.bind("<Button-1>", lambda e: _open("https://ko-fi.com/dannyvandenbrande"))

        github = ttk.Label(
            credit,
            text="https://github.com/DayZ-AutomationZ",
            style="Muted.TLabel",
            anchor="center",
            cursor="hand2"
        )
        github.pack(fill="x")
        github.bind("<Button-1>", lambda e: _open("https://github.com/DayZ-AutomationZ"))

        top=ttk.Frame(right); top.pack(fill="x")
        self.btn_start=ttk.Button(top,text="Start Monitoring",style="Colored.TButton",command=self._toggle); self.btn_start.pack(side="left")
        ttk.Label(top,text="Poll (sec):",style="Muted.TLabel").pack(side="left",padx=(12,4))
        self.v_poll=tk.StringVar(value=str(self.poll_seconds))
        ttk.Entry(top,textvariable=self.v_poll,width=6).pack(side="left")
        self.v_autostart=tk.IntVar(value=1 if self.auto_start else 0)
        ttk.Checkbutton(top,text="Auto-start monitoring",variable=self.v_autostart).pack(side="left",padx=(12,0))
        ttk.Button(top,text="Test Detection",command=self._test_once).pack(side="left",padx=(12,0))

        editor=ttk.LabelFrame(right,text="Selected Target"); editor.pack(fill="x",pady=(10,10))
        grid=ttk.Frame(editor); grid.pack(fill="x",padx=10,pady=10)
        grid.columnconfigure(1,weight=1); grid.columnconfigure(3,weight=1)

        self.sel_index:Optional[int]=None
        self.v_name=tk.StringVar(); self.v_mode=tk.StringVar(value="ftp"); self.v_delay=tk.StringVar(value="10")
        self.v_watch=tk.StringVar(value="newest_mtime"); self.v_exts=tk.StringVar(value=".pbo,.txt,.json")
        self.v_marker=tk.StringVar(value="automationz_last_deploy.txt"); self.v_local=tk.StringVar(); self.v_remote=tk.StringVar(value="/")
        self.v_host=tk.StringVar(); self.v_user=tk.StringVar(); self.v_pass=tk.StringVar(); self.v_port=tk.StringVar(value="21"); self.v_tls=tk.StringVar(value="0")
        self.v_action=tk.StringVar(value="notify"); self.v_cmd=tk.StringVar()
        self.v_rcon_host=tk.StringVar(); self.v_rcon_port=tk.StringVar(value="2305"); self.v_rcon_pass=tk.StringVar(); self.v_rcon_cmd=tk.StringVar(value="#shutdown")
        self.v_rcon_timeout=tk.StringVar(value="6"); self.v_rcon_retries=tk.StringVar(value="3")
        self.v_discord_enabled=tk.IntVar(value=0); self.v_discord_webhook=tk.StringVar()

        def lbl(r,c,t): ttk.Label(grid,text=t).grid(row=r,column=c,sticky="w",padx=(0,6),pady=4)
        def ent(r,c,var,show=None):
            e=ttk.Entry(grid,textvariable=var,show=show if show else "")
            e.grid(row=r,column=c,sticky="ew",pady=4); return e

        lbl(0,0,"Name:"); ent(0,1,self.v_name)
        lbl(0,2,"Mode:")
        cb=ttk.Combobox(grid,textvariable=self.v_mode,values=["ftp","local"],state="readonly",width=8)
        cb.grid(row=0,column=3,sticky="w",pady=4); cb.bind("<<ComboboxSelected>>", lambda e: self._vis())
        lbl(1,0,"Restart delay (min):"); ent(1,1,self.v_delay)
        lbl(1,2,"Detect by:")
        ttk.Combobox(grid,textvariable=self.v_watch,values=["newest_mtime","marker_file"],state="readonly",width=14).grid(row=1,column=3,sticky="w",pady=4)
        lbl(2,0,"Include exts:"); ent(2,1,self.v_exts)
        lbl(2,2,"Marker file:"); ent(2,3,self.v_marker)

        self.local_row=ttk.Frame(grid); self.local_row.grid(row=3,column=0,columnspan=4,sticky="ew",pady=(6,0))
        self.local_row.columnconfigure(1,weight=1)
        ttk.Label(self.local_row,text="Local path:").grid(row=0,column=0,sticky="w",padx=(0,6))
        ttk.Entry(self.local_row,textvariable=self.v_local).grid(row=0,column=1,sticky="ew")
        ttk.Button(self.local_row,text="Browse",command=self._browse).grid(row=0,column=2,padx=(6,0))

        self.ftp_box=ttk.LabelFrame(grid,text="FTP/FTPS"); self.ftp_box.grid(row=4,column=0,columnspan=4,sticky="ew",pady=(8,0))
        self.ftp_box.columnconfigure(1,weight=1); self.ftp_box.columnconfigure(3,weight=1)
        def flbl(r,c,t): ttk.Label(self.ftp_box,text=t).grid(row=r,column=c,sticky="w",padx=(0,6),pady=4)
        def fent(r,c,var,show=None):
            e=ttk.Entry(self.ftp_box,textvariable=var,show=show if show else "")
            e.grid(row=r,column=c,sticky="ew",pady=4); return e
        flbl(0,0,"Host:"); fent(0,1,self.v_host)
        flbl(0,2,"Port:"); fent(0,3,self.v_port)
        flbl(1,0,"User:"); fent(1,1,self.v_user)
        flbl(1,2,"FTPS (0/1):"); fent(1,3,self.v_tls)
        flbl(2,0,"Password:"); fent(2,1,self.v_pass,show="*")
        flbl(2,2,"Remote path:"); fent(2,3,self.v_remote)

        action_box=ttk.LabelFrame(right,text="Action / Restart method"); action_box.pack(fill="x",pady=(0,10))
        agrid=ttk.Frame(action_box); agrid.pack(fill="x",padx=10,pady=10)
        agrid.columnconfigure(1,weight=1); agrid.columnconfigure(3,weight=1)
        ttk.Label(agrid,text="Action:").grid(row=0,column=0,sticky="w",padx=(0,6),pady=4)
        ttk.Combobox(agrid,textvariable=self.v_action,values=["notify","local_command","rcon_command"],state="readonly",width=18).grid(row=0,column=1,sticky="w",pady=4)
        ttk.Label(agrid,text="Command (if local_command):").grid(row=1,column=0,sticky="w",padx=(0,6),pady=4)
        ttk.Entry(agrid,textvariable=self.v_cmd).grid(row=1,column=1,sticky="ew",pady=4)

        rbox=ttk.LabelFrame(agrid,text="BattlEye RCON (if rcon_command)")
        rbox.grid(row=2,column=0,columnspan=4,sticky="ew",pady=(10,0))
        rbox.columnconfigure(1,weight=1); rbox.columnconfigure(3,weight=1)
        def rlbl(r,c,t): ttk.Label(rbox,text=t).grid(row=r,column=c,sticky="w",padx=(0,6),pady=4)
        def rent(r,c,var,show=None):
            e=ttk.Entry(rbox,textvariable=var,show=show if show else "")
            e.grid(row=r,column=c,sticky="ew",pady=4); return e
        rlbl(0,0,"RCON Host/IP:"); rent(0,1,self.v_rcon_host)
        rlbl(0,2,"RCON Port:"); rent(0,3,self.v_rcon_port)
        rlbl(1,0,"RCON Password:"); rent(1,1,self.v_rcon_pass,show="*")
        rlbl(1,2,"Command:"); rent(1,3,self.v_rcon_cmd)
        rlbl(2,0,"Timeout (sec):"); rent(2,1,self.v_rcon_timeout)
        rlbl(2,2,"Retries:"); rent(2,3,self.v_rcon_retries)
        ttk.Button(agrid,text="Test RCON Now",command=self._test_rcon).grid(row=3,column=0,sticky="w",pady=(10,0))

        dbox=ttk.LabelFrame(right,text="Discord notifications (Webhook)"); dbox.pack(fill="x",pady=(0,10))
        dgrid=ttk.Frame(dbox); dgrid.pack(fill="x",padx=10,pady=10); dgrid.columnconfigure(1,weight=1)
        ttk.Checkbutton(dgrid,text="Enable Discord webhook for this target",variable=self.v_discord_enabled).grid(row=0,column=0,columnspan=2,sticky="w",pady=(0,6))
        ttk.Label(dgrid,text="Webhook URL:").grid(row=1,column=0,sticky="w",padx=(0,6))
        ttk.Entry(dgrid,textvariable=self.v_discord_webhook).grid(row=1,column=1,sticky="ew")
        ttk.Button(dgrid,text="Test Discord Now",command=self._test_discord).grid(row=2,column=0,sticky="w",pady=(8,0))

        log_box=ttk.LabelFrame(right,text="Log"); log_box.pack(fill="both",expand=True)
        self.txt=tk.Text(log_box,height=12,bg=C_PANEL,fg=C_TEXT,insertbackground=C_TEXT,relief="flat",wrap="word")
        self.txt.pack(fill="both",expand=True,padx=8,pady=8); self.txt.configure(state="disabled")

        self.status_var=tk.StringVar(value="")
        sb=ttk.Frame(self,style="Panel.TFrame"); sb.pack(fill="x")
        ttk.Label(sb,textvariable=self.status_var,background=C_PANEL,foreground=C_TEXT).pack(side="left",padx=10,pady=6)

        self._vis()

    def _vis(self):
        if self.v_mode.get()=="local":
            self.local_row.grid(); self.ftp_box.grid_remove()
        else:
            self.ftp_box.grid(); self.local_row.grid_remove()

    def _browse(self):
        p=filedialog.askdirectory()
        if p: self.v_local.set(p)

    def _on_close(self):
        try:
            if self.monitor and self.monitor.is_alive(): self.monitor.stop()
        except: pass
        self.destroy()

    def _state_text(self,name:str)->str:
        due=self.pending_until.get(name)
        if due:
            rem=int(due-time.time())
            return "Restarting..." if rem<=0 else f"Restart in {human_secs(rem)}"
        return "OK"

    def _refresh_tree_state(self):
        for iid in self.tree.get_children():
            idx=int(iid)
            name=self.cfg["targets"][idx].get("name","")
            vals=list(self.tree.item(iid,"values"))
            if len(vals)==3:
                vals[2]=self._state_text(name)
                self.tree.item(iid, values=tuple(vals))

    def _load_targets(self):
        for i in self.tree.get_children(): self.tree.delete(i)
        for idx,t in enumerate(self.cfg.get("targets",[])):
            name=t.get("name",f"Target {idx+1}")
            mode=t.get("mode","ftp"); delay=t.get("delay_minutes",10)
            self.tree.insert("", "end", iid=str(idx), values=(mode,f"{delay}m",self._state_text(name)))

    def _on_select(self,_=None):
        sel=self.tree.selection()
        if not sel: return
        self.sel_index=int(sel[0])
        t=self.cfg["targets"][self.sel_index]
        self.v_name.set(t.get("name",""))
        self.v_mode.set(t.get("mode","ftp"))
        self.v_delay.set(str(t.get("delay_minutes",10)))
        self.v_watch.set(t.get("watch_kind","newest_mtime"))
        self.v_exts.set(t.get("include_exts",".pbo,.txt,.json"))
        self.v_marker.set(t.get("marker_file","automationz_last_deploy.txt"))
        self.v_local.set(t.get("local_path",""))
        ftp=t.get("ftp",{}) or {}
        self.v_host.set(ftp.get("host","")); self.v_user.set(ftp.get("user","")); self.v_pass.set(ftp.get("password",""))
        self.v_port.set(str(ftp.get("port",21))); self.v_tls.set(str(ftp.get("tls",0))); self.v_remote.set(t.get("remote_path","/"))
        self.v_action.set(t.get("action","notify")); self.v_cmd.set(t.get("command",""))
        r=t.get("rcon",{}) or {}
        self.v_rcon_host.set(r.get("host","")); self.v_rcon_port.set(str(r.get("port",2305))); self.v_rcon_pass.set(r.get("password",""))
        self.v_rcon_cmd.set(r.get("command","#shutdown")); self.v_rcon_timeout.set(str(r.get("timeout",6))); self.v_rcon_retries.set(str(r.get("retries",3)))
        d=t.get("discord",{}) or {}
        self.v_discord_enabled.set(1 if safe_bool(d.get("enabled",False),False) else 0)
        self.v_discord_webhook.set(d.get("webhook_url","") or "")
        self._q_status(f"Selected: {t.get('name','')}"); self._vis()

    def _collect(self)->Dict[str,Any]:
        return {
            "name": (self.v_name.get().strip() or "Unnamed"),
            "mode": self.v_mode.get(),
            "delay_minutes": safe_int(self.v_delay.get(),10),
            "watch_kind": self.v_watch.get(),
            "include_exts": self.v_exts.get().strip(),
            "marker_file": (self.v_marker.get().strip() or "automationz_last_deploy.txt"),
            "local_path": self.v_local.get().strip(),
            "remote_path": (self.v_remote.get().strip() or "/"),
            "ftp": {"host":self.v_host.get().strip(),"user":self.v_user.get().strip(),"password":self.v_pass.get(),
                    "port":safe_int(self.v_port.get(),21),"tls":safe_int(self.v_tls.get(),0),"timeout":12},
            "action": self.v_action.get(),
            "command": self.v_cmd.get().strip(),
            "rcon": {"host":self.v_rcon_host.get().strip(),"port":safe_int(self.v_rcon_port.get(),2305),
                     "password":self.v_rcon_pass.get(),"command":(self.v_rcon_cmd.get().strip() or "#shutdown"),
                     "timeout":safe_int(self.v_rcon_timeout.get(),6),"retries":safe_int(self.v_rcon_retries.get(),3)},
            "discord": {"enabled": bool(self.v_discord_enabled.get()), "webhook_url": self.v_discord_webhook.get().strip()}
        }

    def _save(self):
        if self.sel_index is None:
            messagebox.showinfo(APP_NAME,"Select a target first."); return
        self.cfg["targets"][self.sel_index]=self._collect()
        self.cfg.setdefault("app",{})["poll_seconds"]=safe_int(self.v_poll.get(),30)
        self.cfg["app"]["auto_start"]=bool(self.v_autostart.get())
        save_config(self.cfg)
        self._q_log("Saved config."); self._load_targets()

    def _add(self):
        self.cfg.setdefault("targets",[]).append(asdict(Target()))
        save_config(self.cfg); self._load_targets(); self._q_log("Added new target.")
        iid=str(len(self.cfg["targets"])-1); self.tree.selection_set(iid); self.tree.see(iid); self._on_select()

    def _delete(self):
        if self.sel_index is None:
            messagebox.showinfo(APP_NAME,"Select a target to delete."); return
        name=self.cfg["targets"][self.sel_index].get("name","")
        if not messagebox.askyesno(APP_NAME,f"Delete target '{name}'?"): return
        del self.cfg["targets"][self.sel_index]; save_config(self.cfg)
        self.sel_index=None; self._load_targets(); self._q_log("Deleted target.")

    def _toggle(self):
        if self.monitor and self.monitor.is_alive():
            self.monitor.stop(); self.monitor=None
            self.btn_start.configure(text="Start Monitoring",style="Colored.TButton")
            self._q_status("Stopped."); self._q_log("Monitoring stopped."); return

        self.poll_seconds=safe_int(self.v_poll.get(),30)
        self.cfg.setdefault("app",{})["poll_seconds"]=self.poll_seconds
        self.cfg["app"]["auto_start"]=bool(self.v_autostart.get())
        save_config(self.cfg)
        self._last_poll=0.0
        self.monitor=MonitorThread(self); self.monitor.start()
        self.btn_start.configure(text="Stop Monitoring",style="Bad.TButton")
        self._q_status(f"Monitoring running. Poll={self.poll_seconds}s.")
        self._q_log(f"Monitoring started. Poll interval: {self.poll_seconds}s.")

    def _test_once(self):
        self._q_log("Manual test: polling all targets now...")
        self.poll_all_targets(force=True)

    def _test_rcon(self):
        if self.sel_index is None:
            messagebox.showinfo(APP_NAME,"Select a target first."); return
        t=self._collect()
        self._q_log("Manual test: sending RCON command now...")
        try:
            out=self._run_rcon_for_target(t)
            self._q_log("RCON command sent (test).","INFO")
            if out: self._q_log(f"RCON response: {out}","INFO")
        except Exception as e:
            self._q_log(f"RCON test failed: {e}","WARN")
            messagebox.showwarning(APP_NAME,f"RCON test failed:\n\n{e}")

    def _test_discord(self):
        if self.sel_index is None:
            messagebox.showinfo(APP_NAME,"Select a target first."); return
        t=self._collect()
        if not self._discord_enabled(t):
            messagebox.showinfo(APP_NAME,"Enable Discord + set a webhook URL first."); return
        try:
            discord_send(self._discord_url(t), f"✅ **{t.get('name','Server')}**: Discord test message from AutomationZ.")
            self._q_log("Discord test message sent.","INFO")
        except Exception as e:
            self._q_log(f"Discord test failed: {e}","WARN")
            messagebox.showwarning(APP_NAME,f"Discord test failed:\n\n{e}")

    def _discord_enabled(self,t):
        d=t.get("discord",{}) or {}
        return safe_bool(d.get("enabled",False),False) and bool((d.get("webhook_url","") or "").strip())
    def _discord_url(self,t): return (t.get("discord",{}) or {}).get("webhook_url","") or ""
    def _discord_notify(self,t,msg):
        if not self._discord_enabled(t): return
        try: discord_send(self._discord_url(t), msg)
        except Exception as e: self._q_log(f"{t.get('name','Server')}: Discord notify failed: {e}","WARN")

    def _run_rcon_for_target(self,t)->str:
        r=t.get("rcon",{}) or {}
        return be_rcon_shutdown(
            (r.get("host","") or "").strip(),
            safe_int(r.get("port",2305),2305),
            r.get("password","") or "",
            (r.get("command","#shutdown") or "#shutdown").strip(),
            timeout=safe_int(r.get("timeout",6),6),
            retries=safe_int(r.get("retries",3),3),
        )

    def poll_all_targets(self, force:bool=False):
        tlist=self.cfg.get("targets",[])
        if not tlist: return
        now=time.time()
        if not force and (now-self._last_poll)<self.poll_seconds: return
        self._last_poll=now
        for t in tlist:
            name=t.get("name","Unnamed")
            try:
                changed,current=self._check(t)
                if current is not None: self.last_seen.setdefault(name,current)
                if changed: self._schedule(t)
            except Exception as e:
                self._q_log(f"{name}: check failed: {e}","WARN")
        self._q_refresh()

    def _check(self,t)->Tuple[bool,Optional[int]]:
        name=t.get("name","Unnamed")
        mode=t.get("mode","ftp")
        watch=t.get("watch_kind","newest_mtime")
        exts=[x.strip().lower() for x in (t.get("include_exts","") or "").split(",") if x.strip()]
        marker=t.get("marker_file","automationz_last_deploy.txt")
        current=None
        if mode=="local":
            root=Path(t.get("local_path","")).expanduser()
            if not root.exists(): raise RuntimeError(f"Local path not found: {root}")
            current = marker_mtime_local(root, marker) if watch=="marker_file" else newest_mtime_local(root, exts)
        else:
            ftp_cfg=FTPConfig(**(t.get("ftp",{}) or {}))
            remote=t.get("remote_path","/") or "/"
            if not ftp_cfg.host: raise RuntimeError("FTP host is empty")
            current = marker_mtime_ftp(ftp_cfg, remote, marker) if watch=="marker_file" else newest_mtime_ftp(ftp_cfg, remote, exts)

        prev=self.last_seen.get(name)
        if prev is None:
            if current is not None:
                self.last_seen[name]=current
                self._q_log(f"{name}: baseline set.","INFO")
            return (False,current)
        if current is None:
            self._q_log(f"{name}: could not read timestamp (limited access).","WARN")
            return (False,None)
        if current>prev:
            self.last_seen[name]=current
            self._q_log(f"{name}: UPDATE detected.","INFO")
            return (True,current)
        return (False,current)

    def _schedule(self,t):
        name=t.get("name","Unnamed")
        delay=safe_int(t.get("delay_minutes",10),10)
        self.pending_until[name]=time.time()+delay*60
        self._q_log(f"{name}: restart timer set to {delay} minutes (resets on new updates).","INFO")
        self._q_status(f"Update detected for '{name}'. Restart scheduled in {delay} min.")

    def tick_countdowns(self):
        now=time.time(); fired=False
        for t in self.cfg.get("targets",[]):
            name=t.get("name","Unnamed")
            due=self.pending_until.get(name)
            if not due: continue
            if now>=due:
                self.pending_until[name]=None
                fired=True
                self._execute(t)
        if fired: self._q_refresh()

    def _execute(self,t):
        name=t.get("name","Unnamed")
        action=t.get("action","notify")
        if action=="local_command":
            cmd=(t.get("command","") or "").strip()
            if not cmd:
                self._q_log(f"{name}: No command set. Falling back to notify.","WARN")
                self._discord_notify(t, f"⚠️ **{name}**: No local command set. `RESTART NEEDED now. (Use host panel/app)`")
                self._q_log(f"{name}: RESTART NEEDED now. (Use host panel/app)","WARN")
                return
            self._q_log(f"{name}: Running command: {cmd}","INFO")
            rc=os.system(cmd)
            self._q_log(f"{name}: Command finished (exit code {rc}).","INFO")
            self._discord_notify(t, f"✅ **{name}**: Local restart command executed. Exit code: `{rc}`")
            return

        if action=="rcon_command":
            self._q_log(f"{name}: Sending BattlEye RCON command...","INFO")
            try:
                out=self._run_rcon_for_target(t)
                if out: self._q_log(f"{name}: RCON response: {out}","INFO")
                else: self._q_log(f"{name}: RCON command sent (no response text).","INFO")
                self._discord_notify(t, f"✅ **{name}**: Server has been restarted via RCON.")
                return
            except Exception as e:
                self._q_log(f"{name}: RCON failed: {e}","WARN")
                self._discord_notify(t, f"❌ **{name}**: Failed to connect to RCON. ({e})")
                self._discord_notify(t, f"⚠️ **{name}**: `RESTART NEEDED now. (Use host panel/app)`")
                self._q_log(f"{name}: RESTART NEEDED now. (Use host panel/app)","WARN")
                return

        self._discord_notify(t, f"⚠️ **{name}**: `RESTART NEEDED now. (Use host panel/app)`")
        self._q_log(f"{name}: RESTART NEEDED now. (Use host panel/app)","WARN")

def main():
    App().mainloop()

if __name__=="__main__":
    main()
