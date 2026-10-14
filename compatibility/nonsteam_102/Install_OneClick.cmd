@echo off
setlocal
if "%~1"=="" (
  echo Drag the game folder onto this script, or pass the game folder and saved original EXE as arguments.
  exit /b 2
)
if "%~2"=="" (
  py -3 "%~dp0patcher.py" apply --game-dir "%~1"
) else (
  py -3 "%~dp0patcher.py" apply --game-dir "%~1" --original-exe "%~2"
)
set "RC=%errorlevel%"
if not "%RC%"=="0" pause
exit /b %RC%
