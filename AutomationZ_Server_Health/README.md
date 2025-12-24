# AutomationZ Server Health

A lightweight **server log health monitor** for DayZ server owners (and any FTP/FTPS accessible server).

## What it does
- Fetches log files via **FTP/FTPS** (or reads local paths)
- Tails only new content (offset tracking)
- Detects **errors / exceptions / crash signatures**
- Stores a small event history
- Optional **Discord webhook notifications**

## How to run
### Windows
Double-click:
- `run_windows.bat`

### Linux/macOS
Run:
- `./run_linux_mac.sh`

## Setup
1. Edit `config/profiles.json` (FTP credentials + root)
2. Edit `config/watches.json` (log files to monitor)
3. (Optional) add your webhook in `config/settings.json`

Created by Danny van den Brande.
