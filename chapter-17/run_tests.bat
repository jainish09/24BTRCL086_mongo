@echo off
echo ========================================================
echo Running Chapter 17 Vector Search & RAG Tests
echo ========================================================
cd /d "%~dp0\.."
pytest tests/test_chapter17.py -v
pause

