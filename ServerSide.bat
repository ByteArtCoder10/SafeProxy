@echo off
TITLE SafeProxy - Server side

d:
cd SafeProxy

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Starting Server side...
python -m main

pause