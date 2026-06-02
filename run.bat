@echo off
REM Run the RGB controller GUI via Windows Python.
REM Called from WSL: cmd.exe /c run.bat
REM Or directly from Windows / Task Scheduler.

set SCRIPT_DIR=%~dp0
python "%SCRIPT_DIR%main.py" %*
