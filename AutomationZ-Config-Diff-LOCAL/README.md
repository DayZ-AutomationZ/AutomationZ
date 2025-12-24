This tool never modifies your files — it only copies and compares them.
# AutomationZ Config Diff [![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R51QD7BU)

**This tool was originally built for my DayZ server to compare backups of configuration files and folders before and after making changes.
By creating snapshots of files at different moments in time, I can easily compare a working state with a broken one and see exactly what changed in a clear report.
When something breaks, I simply download the current files, create two snapshots, run a comparison, and immediately know what was added, removed, or modified.
No DayZ mod is required.
Although designed with DayZ servers in mind, this tool works for any game server, website, application, or system that uses folders and files — making it a universal configuration diff and troubleshooting tool.**

[![Config_Diff_Set_name.png](https://i.postimg.cc/x8Ytps1q/Config_Diff_Set_name.png)](https://postimg.cc/JD6NG5JW)

**AutomationZ Config Diff** is a lightweight **snapshot + compare (diff)** tool for server admins and modders.
It helps you quickly answer the question:

> **“What changed between version A and version B?”**

It’s perfect for debugging **broken loot**, **wrong settings**, **DayZ updates**, **wipes**, or accidental edits.

✅ Works on **Windows / Linux / macOS**  
✅ Creates clean **Markdown diff reports** you can share  
✅ Beginner-friendly workflow

---

## What this tool is for

### DayZ server admins
- Compare `cfggameplay.json`, `types.xml`, `events.xml`
- Track changes after updates, wipes, or mod edits

### Any folder comparison
- Snapshot folders before changes
- Snapshot again after
- Diff to instantly see what broke

---

## How it works

1. **init** – creates `config/settings.json`
2. **snapshot** – copies tracked files into `snapshots/`
3. **diff** – compares two snapshots and writes a Markdown report

Nothing is modified. Files are only copied and compared.

---

## Quick Start

### Windows
Run:
- `run_windows.bat`

### Linux / macOS
```bash
python3 app/main.py
```

---

## Typical workflow

1. Init
2. Edit settings.json
3. Snapshot BEFORE
4. Make changes
5. Snapshot AFTER
6. Diff and read report

### Typical Use Case

1. Download a backup of your server files
2. Create a snapshot (`before_update`)
3. Make changes or update your server
4. Download the new files
5. Create another snapshot (`after_update`)
6. Run a diff and review the generated report

---

## Hosted servers (Nitrado etc.)

Download configs via FTP → snapshot → change → download again → snapshot → diff.

---

## FAQ

**Is this a DayZ mod?**  
No.

**Does it change my server files?**  
No.

**Does it work on Linux?**  
Yes.

---
🧩 Part of AutomationZ Control Center
This tool is part of the AutomationZ Admin Toolkit:

- AutomationZ Mod Update Auto Deploy (steam workshop)
- AutomationZ Uploader
- AutomationZ Scheduler
- AutomationZ Server Backup Scheduler
- AutomationZ Server Health
- AutomationZ Config Diff 
- AutomationZ Admin Orchestrator
- AutomationZ Log Cleanup Scheduler

Together they form a complete server administration solution.

### 💚 Support the project

AutomationZ tools are built for server owners by a server owner.  
If these tools save you time or help your community, consider supporting development.

☕ Ko-fi: https://ko-fi.com/dannyvandenbrande  
💬 Discord: https://discord.gg/6g8EPES3BP  

Created by **Danny van den Brande**  
DayZ AutomationZ


Part of the **AutomationZ** project  
Built to reduce admin workload and remove unnecessary manual server management.

If this tool saves you time or stress, consider supporting development.
[![ko-fi](https://ko-fi.com/img/githubbutton_sm.svg)](https://ko-fi.com/R6R51QD7BU)

☕ Ko-fi: https://ko-fi.com/dannyvandenbrande  
💬 Discord: https://discord.gg/6g8EPES3BP  

Created by **Danny van den Brande**  
DayZ AutomationZ
