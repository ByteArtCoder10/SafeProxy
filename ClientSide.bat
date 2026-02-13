@echo off
TITLE SafeProxy - Client side


echo Activating virtual environment...
call venv\Scripts\activate.bat

echo Starting Client side...
: flet run -m -r -d src.client.ui.main

: without hot reload:
flet run -w -m src.client.ui.main 

pause