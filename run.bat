@echo off

rem ------------------------------------------------------------
rem Run script for AegisCert Django project
rem ------------------------------------------------------------

rem Change to project root (assumes script is placed in the project root)
cd /d "%~dp0"

rem Activate virtual environment
call .venv\Scripts\activate.bat

rem Start Django development server
python manage.py runserver

pause
