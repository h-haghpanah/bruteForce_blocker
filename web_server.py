from flask import Flask, request, jsonify, render_template
import sqlite3
from decouple import config
from datetime import datetime
import os

app = Flask(__name__)

DB_FILE = config("SQLITE_DB_FILE", cast=str, default="bruteforce.db")

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
TEMPLATES_DIR = os.path.join(BASE_DIR, "templates")
STATIC_DIR = os.path.join(BASE_DIR, "static")
app.template_folder = TEMPLATES_DIR
app.static_folder = STATIC_DIR


def query_alerts(start_date=None, end_date=None):
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    c = conn.cursor()

    if start_date and end_date:
        sql = "SELECT * FROM alerts WHERE date(created_at) BETWEEN ? AND ? ORDER BY created_at DESC"
        params = (start_date, end_date)
    elif start_date:
        sql = "SELECT * FROM alerts WHERE date(created_at) >= ? ORDER BY created_at DESC"
        params = (start_date,)
    elif end_date:
        sql = "SELECT * FROM alerts WHERE date(created_at) <= ? ORDER BY created_at DESC"
        params = (end_date,)
    else:
        sql = "SELECT * FROM alerts ORDER BY created_at DESC LIMIT 1000"
        params = ()

    c.execute(sql, params)
    rows = c.fetchall()
    conn.close()
    return [dict(r) for r in rows]


@app.route('/')
def index():
    return render_template("index.html", db_file=DB_FILE)


@app.route('/data', methods=['POST'])
def data():
    start = request.form.get('start') or request.json and request.json.get('start')
    end = request.form.get('end') or request.json and request.json.get('end')

    def valid_date(s):
        if not s:
            return False
        try:
            datetime.strptime(s, '%Y-%m-%d')
            return True
        except Exception:
            return False

    sd = start if valid_date(start) else None
    ed = end if valid_date(end) else None

    rows = query_alerts(sd, ed)

    return jsonify({
        'data': rows
    })
