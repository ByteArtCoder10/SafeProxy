@echo off
TITLE SafeProxy - Client side

d:
cd SafeProxy

echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Starting Client side...
flet run -m -r -d src.client.ui.main

pause