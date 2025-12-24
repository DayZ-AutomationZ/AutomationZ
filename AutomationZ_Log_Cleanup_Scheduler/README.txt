# LogCleanupScheduler (GUI)

A simple GUI **Log Delete Scheduler** (local + FTP/FTPS).

## What it does
- Define multiple **Jobs**
- Each job can clean:
  - **Local** folders (Windows/Linux/Raspberry Pi)
  - **FTP/FTPS** folders (remote server)
- Schedule jobs by **days + time**
- Exclude (blacklist) files like config files that live inside log folders.

## Folder structure
- `app/main.py` -> the GUI program
- `config/log_cleanup_config.json` -> auto-created on first run
- `logs/` -> app logs

## Requirements
- Python 3.9+ recommended
- Tkinter installed
  - Windows/macOS usually includes it
  - Debian/RPi: `sudo apt install python3-tk`

## Run
### Windows
Double-click `launchers/run_windows.bat`
or run:
`py app\main.py`

### Linux / Raspberry Pi
`chmod +x launchers/run_linux.sh`
`./launchers/run_linux.sh`
or:
`python3 app/main.py`

## Exclude patterns
- Exclude files supports wildcards:
  - `*.json`, `*.cfg`, `*.xml`, `keep_me.txt`
- Exclude folders is by folder **name**:
  - `config`, `settings`

## Safety
Use **Dry run** first (enabled by default):
- It will log what would be deleted
- No deletion happens until you disable Dry run for that job

## Notes
- FTP mode deletes files and will remove **empty subfolders** (unless excluded).
- If your FTP server does not support `MLSD`, it falls back to `NLST` and a directory test.
