@echo off
echo ===========================================
echo DDoS Monitor - Test Runner
echo ===========================================
echo.

pytest ..\tests\ -v -s

echo.
pause
