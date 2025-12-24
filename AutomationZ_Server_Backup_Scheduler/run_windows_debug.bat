@echo off
setlocal
cd /d "%~dp0"
where py
where python
py -X faulthandler app\main.py
pause
