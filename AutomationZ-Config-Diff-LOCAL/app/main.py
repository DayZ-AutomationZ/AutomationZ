#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import sys
import shutil
import datetime
from pathlib import Path
from typing import Dict, Any, List, Tuple
import difflib
import re

APP_NAME = "AutomationZ Config Diff"
APP_VERSION = "1.0.1"

BASE_DIR = Path(__file__).resolve().parent.parent
CONFIG_DIR = BASE_DIR / "config"
SNAP_DIR = BASE_DIR / "snapshots"
REPORTS_DIR = BASE_DIR / "reports"

SETTINGS_PATH = CONFIG_DIR / "settings.json"

# --------------------------- helpers ---------------------------

def now_stamp() -> str:
    return datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

def load_settings() -> Dict[str, Any]:
    if not SETTINGS_PATH.exists():
        SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
        default = {
            "project_name": "My DayZ Server",
            "root_path": "",
            "files": [
                # Add/adjust your local file paths here (relative to root_path if root_path is set)
                {"name": "cfggameplay.json", "path": "cfggameplay.json"},
                {"name": "types.xml", "path": "types.xml"},
                {"name": "events.xml", "path": "events.xml"},
                {"name": "messages.xml", "path": "messages.xml"},
                {"name": "BBP_Settings.json", "path": "BBP_Settings.json"}
            ]
        }
        SETTINGS_PATH.write_text(json.dumps(default, indent=4), encoding="utf-8")
    return json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))

def save_settings(obj: Dict[str, Any]) -> None:
    SETTINGS_PATH.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_PATH.write_text(json.dumps(obj, indent=4), encoding="utf-8")

def resolve_path(root: str, p: str) -> Path:
    p = p.strip()
    if not p:
        raise ValueError("Empty file path in settings.json")
    path = Path(p)
    if root.strip():
        path = Path(root) / p
    return path

def safe_name(s: str) -> str:
    s = s.strip()
    s = re.sub(r"[^a-zA-Z0-9_\-\. ]+", "_", s)
    s = re.sub(r"\s+", "_", s)
    return s or "snapshot"

def read_text_bytes(path: Path) -> Tuple[bytes, str]:
    data = path.read_bytes()
    # try utf-8 with BOM, fallback to latin-1 for odd logs
    try:
        text = data.decode("utf-8-sig")
    except Exception:
        text = data.decode("latin-1", errors="replace")
    return data, text

def normalize_for_diff(text: str, ext: str) -> List[str]:
    # Lightweight normalizers (no heavy dependencies)
    # JSON: try load+dump sorted keys
    if ext.lower() == ".json":
        try:
            obj = json.loads(text)
            norm = json.dumps(obj, indent=2, sort_keys=True, ensure_ascii=False)
            return norm.splitlines(keepends=True)
        except Exception:
            return text.splitlines(keepends=True)

    # XML: normalize whitespace between tags so diffs are cleaner
    if ext.lower() in (".xml", ".html", ".htm"):
        # Remove trailing spaces and collapse empty lines
        lines = [ln.rstrip() + "\n" for ln in text.splitlines()]
        # Keep as-is but trimmed
        return lines

    # default: raw lines
    return text.splitlines(keepends=True)

def copy_into_snapshot(root: str, files: List[Dict[str, str]], snap_dir: Path) -> List[str]:
    snap_dir.mkdir(parents=True, exist_ok=True)
    copied = []
    for f in files:
        name = f.get("name","Unnamed")
        rel = f.get("path","").strip()
        src = resolve_path(root, rel)
        if not src.exists():
            copied.append(f"[MISSING] {name}: {src}")
            continue
        # preserve relative structure
        dest = snap_dir / rel.replace("\\","/")
        dest.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(src, dest)
        copied.append(f"[OK] {name}: {src} -> {dest}")
    return copied

def diff_two_snapshots(a: Path, b: Path, out_dir: Path) -> Path:
    out_dir.mkdir(parents=True, exist_ok=True)
    report_path = out_dir / f"diff_{a.name}__VS__{b.name}.md"

    # gather files union
    files_a = {p.relative_to(a).as_posix(): p for p in a.rglob("*") if p.is_file()}
    files_b = {p.relative_to(b).as_posix(): p for p in b.rglob("*") if p.is_file()}
    all_keys = sorted(set(files_a.keys()) | set(files_b.keys()))

    lines = []
    lines.append(f"# {APP_NAME} — Diff Report\n\n")
    lines.append(f"- A: `{a.name}`\n")
    lines.append(f"- B: `{b.name}`\n")
    lines.append(f"- Generated: `{datetime.datetime.now().isoformat(sep=' ', timespec='seconds')}`\n\n")

    added = [k for k in all_keys if k not in files_a and k in files_b]
    removed = [k for k in all_keys if k in files_a and k not in files_b]
    common = [k for k in all_keys if k in files_a and k in files_b]

    lines.append("## Summary\n\n")
    lines.append(f"- Added files: **{len(added)}**\n")
    lines.append(f"- Removed files: **{len(removed)}**\n")
    lines.append(f"- Compared files: **{len(common)}**\n\n")

    if added:
        lines.append("### Added\n\n")
        for k in added:
            lines.append(f"- `{k}`\n")
        lines.append("\n")

    if removed:
        lines.append("### Removed\n\n")
        for k in removed:
            lines.append(f"- `{k}`\n")
        lines.append("\n")

    lines.append("## File Diffs\n\n")

    for k in common:
        pa = files_a[k]
        pb = files_b[k]
        ba, ta = read_text_bytes(pa)
        bb, tb = read_text_bytes(pb)
        if ba == bb:
            continue  # identical

        ext = Path(k).suffix
        la = normalize_for_diff(ta, ext)
        lb = normalize_for_diff(tb, ext)

        ud = difflib.unified_diff(la, lb, fromfile=f"A/{k}", tofile=f"B/{k}", lineterm="")
        diff_text = "\n".join(ud)

        lines.append(f"### `{k}`\n\n")
        lines.append("```diff\n")
        # Limit per-file diff to keep report readable
        max_chars = 20000
        if len(diff_text) > max_chars:
            lines.append(diff_text[:max_chars] + "\n... (truncated)\n")
        else:
            lines.append(diff_text + "\n")
        lines.append("```\n\n")

    if report_path:
        report_path.write_text("".join(lines), encoding="utf-8")
    return report_path

# --------------------------- CLI ---------------------------

def cmd_init(args: argparse.Namespace) -> int:
    s = load_settings()
    print(f"{APP_NAME} v{APP_VERSION}")
    print("Created settings at:", SETTINGS_PATH)
    print("\nEdit this file to point to your local DayZ config files.")
    if not s.get("root_path"):
        print("\nTip: set root_path to your server config folder so file paths can be relative.")
    return 0

def cmd_snapshot(args: argparse.Namespace) -> int:
    s = load_settings()
    root = s.get("root_path","")
    files = s.get("files", [])
    name = safe_name(args.name or now_stamp())
    snap_dir = SNAP_DIR / name
    results = copy_into_snapshot(root, files, snap_dir)
    print(f"Snapshot created: {snap_dir}")
    for r in results:
        print(" ", r)
    # write manifest
    manifest = {
        "app": {"name": APP_NAME, "version": APP_VERSION},
        "created": datetime.datetime.now().isoformat(sep=" ", timespec="seconds"),
        "project_name": s.get("project_name",""),
        "root_path": root,
        "files": files
    }
    (snap_dir / "_manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return 0

def cmd_diff(args: argparse.Namespace) -> int:
    a = SNAP_DIR / args.a
    b = SNAP_DIR / args.b
    if not a.exists() or not a.is_dir():
        print("Snapshot A not found:", a)
        return 2
    if not b.exists() or not b.is_dir():
        print("Snapshot B not found:", b)
        return 2
    report = diff_two_snapshots(a, b, REPORTS_DIR)
    print("Report written:", report)
    return 0

def interactive_menu() -> int:
    print("""
 █████╗ ██╗   ██╗████████╗ ██████╗ ███╗   ███╗ █████╗ ████████╗██╗ ██████╗ ███╗   ██╗███████╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗████╗ ████║██╔══██╗╚══██╔══╝██║██╔═══██╗████╗  ██║╚══███╔╝
███████║██║   ██║   ██║   ██║   ██║██╔████╔██║███████║   ██║   ██║██║   ██║██╔██╗ ██║  ███╔╝
██╔══██║██║   ██║   ██║   ██║   ██║██║╚██╔╝██║██╔══██║   ██║   ██║██║   ██║██║╚██╗██║ ███╔╝
██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║ ╚═╝ ██║██║  ██║   ██║   ██║╚██████╔╝██║ ╚████║███████╗
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝   ╚═╝   ╚═╝ ╚═════╝ ╚═╝  ╚═══╝╚══════╝

                     CONFIG DIFF • SNAPSHOTS • DIAGNOSIS
                 See what changed. Know why it broke. Fix it fast.

                         Created by Danny van den Brande
""")


    print(f"\n{APP_NAME} v{APP_VERSION}")
    print("1) init      - create settings.json")
    print("2) snapshot  - copy configured files into snapshots/")
    print("3) diff      - compare two snapshots")
    print("4) open      - open snapshots / reports folders")
    print("5) help      - show CLI help")
    print("0) exit\n")

    choice = input("Select: ").strip()
    if choice == "1":
        return cmd_init(argparse.Namespace())
    if choice == "2":
        name = input("Snapshot name (enter for timestamp): ").strip()
        return cmd_snapshot(argparse.Namespace(name=name))
    if choice == "3":
        print("\nAvailable snapshots:")
        snaps = [p.name for p in SNAP_DIR.iterdir()] if SNAP_DIR.exists() else []
        for n in snaps:
            print(" -", n)
        a = input("\nSnapshot A name: ").strip()
        b = input("Snapshot B name: ").strip()
        if not a or not b:
            print("Both snapshot names are required.")
            return 2
        return cmd_diff(argparse.Namespace(a=a, b=b))
    if choice == "4":
        print("Snapshots:", SNAP_DIR)
        print("Reports  :", REPORTS_DIR)
        return 0
    if choice == "5":
        print("\nCLI examples:")
        print("  python app/main.py init")
        print("  python app/main.py snapshot --name before_update")
        print("  python app/main.py diff --a before_update --b after_update\n")
        return 0
    return 0

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="config_diff", add_help=True)
    sub = p.add_subparsers(dest="cmd")

    sp = sub.add_parser("init", help="Create config/settings.json (if missing)")
    sp.set_defaults(func=cmd_init)

    sp = sub.add_parser("snapshot", help="Create a snapshot from local files configured in settings.json")
    sp.add_argument("--name", default="", help="Snapshot folder name (default: timestamp)")
    sp.set_defaults(func=cmd_snapshot)

    sp = sub.add_parser("diff", help="Diff two snapshots (by folder name under snapshots/)")
    sp.add_argument("--a", required=True, help="Snapshot A folder name")
    sp.add_argument("--b", required=True, help="Snapshot B folder name")
    sp.set_defaults(func=cmd_diff)

    return p

def main(argv: List[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # If launched by double-click / bat with no args -> interactive menu
    if not argv:
        try:
            return interactive_menu()
        except KeyboardInterrupt:
            return 0

    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "cmd", None):
        parser.print_help()
        return 2
    return int(args.func(args))

if __name__ == "__main__":
    raise SystemExit(main())
