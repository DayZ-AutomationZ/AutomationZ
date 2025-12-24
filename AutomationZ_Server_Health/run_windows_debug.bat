@echo off
setlocal
cd /d "%~dp0"
echo Working dir: %CD%
where py
where python
echo Running...
py -3 app\main.py
echo.
echo ---- Program exited ----
pause
