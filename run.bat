@echo off
IF NOT EXIST .venv (
  python -m venv .venv
)
call .venv\Scripts\activate
pip install -r requirements.txt
set FLASK_APP=app.py
flask run
