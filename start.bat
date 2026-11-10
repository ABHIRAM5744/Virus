@echo off
title VIRUS Voice SOC
cd /d "%~dp0"

set PY=python
where python >nul 2>nul || set PY=py
where %PY% >nul 2>nul || (
  echo Python 3.9+ was not found. Install it from https://www.python.org/downloads/ and tick "Add python.exe to PATH".
  pause
  exit /b 1
)

if not exist ".venv\Scripts\activate.bat" (
  echo First run: creating environment...
  %PY% -m venv .venv || (echo Could not create the virtual environment. & pause & exit /b 1)
)
call ".venv\Scripts\activate.bat"

echo Installing / checking packages...
python -m pip install -q -r requirements.txt || (echo Package install failed. Check your internet connection. & pause & exit /b 1)

echo Starting VIRUS Voice SOC... the browser will open in a few seconds.
start "" cmd /c "timeout /t 6 /nobreak >nul & start http://localhost:5000"
python app.py
echo.
echo Server stopped.
pause
