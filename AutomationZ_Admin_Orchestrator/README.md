# AutomationZ Admin Orchestrator (Fixed build)

This build fixes the “doesn’t open / incomplete folders” issue and adds **Local mode** + a **Settings** tab.

## Run (Windows)
1. Install Python 3.10+ from python.org (tick **Add python to PATH**)
2. Double click: `run_windows.bat`

## Run (Linux / Raspberry Pi)
```bash
chmod +x run_linux.sh
./run_linux.sh
```

## Folder layout
- `app/main.py` — the GUI app
- `config/` — auto-created JSON files (profiles, plans, mappings, etc.)
- `presets/<PresetName>/...` — your file presets
- `backups/` — backups taken before overwriting remote/local files
- `logs/` — run logs

## Local mode (no FTP)
In **Profiles**:
- Tick **Local mode**
- Set **Local root folder** to your server folder.
Mappings will be applied into:
`<Local root>/<mapping.remote_path>`

## Notes
- Verify mode currently only runs on FTP targets.
- RCON and Nitrado restart are optional (per plan).
