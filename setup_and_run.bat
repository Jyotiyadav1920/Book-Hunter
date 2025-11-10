@echo off
python -m venv .venv
call .venv\Scripts\activate
pip install -r requirements.txt
python init_db.py
set FLASK_APP=app.py
flask run
