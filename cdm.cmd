@echo off
rem Cathodemon's short command. Type "cdm help" to see what it can do.
rem In PowerShell, run it from this folder as .\cdm
setlocal
set "PYTHONPATH=%~dp0;%PYTHONPATH%"
python -m cathodemon %*
