@echo off
setlocal
cd /d "%~dp0"

rem ---- commit message: use the argument if given, else a timestamp ----
set "MSG=%~1"
if "%MSG%"=="" set "MSG=update %date% %time%"

git add -A

rem ---- commit only if something is staged; keep going either way, because
rem ---- the remote may still be ahead (files created via the GitHub web UI)
git diff --cached --quiet
if errorlevel 1 (
    git commit -m "%MSG%"
    if errorlevel 1 goto :fail
) else (
    echo Nothing to commit locally.
)

rem ---- pull first: this is what fails a push when LICENSE.md / SECURITY.md
rem ---- and friends were created directly on GitHub
echo.
echo Syncing with remote...
git pull --rebase
if errorlevel 1 (
    echo.
    echo *** PULL/REBASE FAILED
    echo *** Resolve the conflicts, then run:  git rebase --continue
    echo *** To abandon the rebase:            git rebase --abort
    goto :fail
)

git push -u origin HEAD
if errorlevel 1 goto :fail

echo.
echo Done.
pause
exit /b 0

:fail
echo.
echo *** FAILED - see the error above. Nothing was pushed.
pause
exit /b 1
