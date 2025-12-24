# AutomationZ Scheduler (v1.0.0)

A separate, clean automation app for scheduled FTP/FTPS uploads.

This is designed to be used alongside **AutomationZ Uploader**:
- **Uploader** = manual uploads (stable + simple)
- **Scheduler** = automated uploads (set tasks, leave it running)

## What it automates
- Weekend raid ON/OFF switches (BBP_Settings.json, cfggameplay.json, etc.)
- Daily rotation configs (loadouts, messages, notifications, loot profiles)
- Any file you can upload via FTP

## How it works
A task triggers at: **day(s) + hour + minute**

When it triggers, it uploads:
`<Presets Folder>/<Task Preset>/<mapping.local_relpath>`  
to:  
`<Profile Root>/<mapping.remote_path>`

## Important notes
- App must be running for automation to happen (v1.0.0).
- No DayZ mod required.
- Uses JSON configs compatible with the Uploader format.

## Files
- `config/profiles.json` — FTP server logins and root folders
- `config/mappings.json` — what local file overwrites what remote file
- `config/tasks.json` — schedule definitions
- `config/settings.json` — tick speed + presets folder location

## Run
### Windows
Double-click `run_windows.bat`.

### Linux / macOS
```bash
chmod +x run_linux_mac.sh
./run_linux_mac.sh
```

## Tip: share presets with Uploader
In **Settings**, set **Presets folder** to the same `presets/` directory you use in the manual Uploader.
