@echo off
echo ========================================================
echo Running Chapter 16 Cassandra & Neo4j Fraud Graph Tests
echo ========================================================
cd /d "%~dp0\.."
pytest tests/test_chapter16.py -v
pause

