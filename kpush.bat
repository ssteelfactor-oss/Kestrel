@echo off
setlocal
cd /d "%~dp0"

rem ── commit message: use the argument if given, else a timestamp ──
set "MSG=%~1"
if "%MSG%"=="" set "MSG=update %date% %time%"

git add -A

rem ── nothing staged? stop quietly ──
git diff --cached --quiet && (
    echo Nothing to commit.
    pause
    exit /b 0
)

git commit -m "%MSG%"
git push -u origin HEAD

echo.
echo Done.
pause
