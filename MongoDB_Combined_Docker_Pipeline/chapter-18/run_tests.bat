@echo off
echo ========================================================
echo Running Chapter 18 Comparative Capstone Tests
echo ========================================================
cd /d "%~dp0\.."
pytest tests/test_chapter18.py -v
pause
