@echo off
setlocal
if "%~1"=="" (
  echo Drag the same game folder onto this script, or pass the game folder as an argument.
  exit /b 2
)
py -3 "%~dp0patcher.py" rollback --game-dir "%~1"
set "RC=%errorlevel%"
if not "%RC%"=="0" pause
exit /b %RC%
