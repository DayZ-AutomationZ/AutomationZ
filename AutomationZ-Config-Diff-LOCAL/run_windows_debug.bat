@echo off
setlocal
cd /d "%~dp0"
echo Working dir: %cd%
where py
echo.
py -3 app\main.py
echo.
echo ---- Program exited ----
pause
