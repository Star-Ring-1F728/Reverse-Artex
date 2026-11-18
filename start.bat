@echo off
setlocal
cd /d "%~dp0"
if not exist "reverse-artex.exe" (
  echo Reverse Artex binary not found. Run build.bat first.
  pause
  exit /b 1
)
"%~dp0reverse-artex.exe" -console -config config.json %*
set "result=%ERRORLEVEL%"
if not "%result%"=="0" (
  echo Reverse Artex stopped with exit code %result%.
  pause
)
exit /b %result%
