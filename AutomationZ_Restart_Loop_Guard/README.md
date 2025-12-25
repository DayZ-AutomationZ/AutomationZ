# AutomationZ Restart Loop Guard (UI)

Restart Loop Guard protects your automation from **infinite restart loops**.

It does **not** detect crashes — it guards **restart/start attempts** on the machine where it runs (local only).

## What it does
- Tracks restart/start attempts inside a rolling time window
- Locks further attempts when the configured threshold is reached
- Persists lock across reboots (manual unlock required)
- Writes an incident report + log
- Optional Discord notification (webhook)

## Local-only (important)
This tool tracks attempts on **this machine**.
It does **not** monitor remote servers/processes by itself.

## Run
```bash
cd app
python3 main.py
```
