# Run the RGB controller GUI via Windows Python.
# From WSL: powershell.exe -File run.ps1
# Or directly in PowerShell on Windows.

$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Definition
python "$ScriptDir\main.py" @args
