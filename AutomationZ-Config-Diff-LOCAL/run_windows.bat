@echo off
setlocal
cd /d "%~dp0"

:menu
cls
py -3 app\main.py
echo.
choice /c YN /m "Return to menu?"
if errorlevel 2 goto end
goto menu

:end
endlocal
