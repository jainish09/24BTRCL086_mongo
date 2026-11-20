@echo off
echo ========================================================
echo Running Chapter 15 Multi-Tenant Case Management Tests
echo ========================================================
cd /d "%~dp0\.."
pytest tests/test_chapter15.py -v
pause
