@echo off
rem Windows launcher for hotpot.py (needs Python 3.10+ from python.org or the Microsoft Store)
setlocal
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 "%~dp0hotpot.py" %*
) else (
  python "%~dp0hotpot.py" %*
)
exit /b %errorlevel%
