@echo off
REM Install required packages
pip install -r requirements.txt

REM Execute Python script
python "url_risk_adviser.py"

pause