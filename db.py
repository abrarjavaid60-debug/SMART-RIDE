"""SQLite access layer (the 'data layer' of the architecture)."""
import os
import sqlite3

from flask import current_app, g

SCHEMA = os.path.join(os.path.dirname(__file__), "schema.sql")


def get_db():
    if "db" not in g:
        # isolation_level=None -> autocommit; services use explicit BEGIN IMMEDIATE
        conn = sqlite3.connect(current_app.config["DATABASE"], isolation_level=None, timeout=15)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys = ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def init_db():
    with open(SCHEMA, encoding="utf-8") as f:
        get_db().executescript(f.read())


def init_app(app):
    app.teardown_appcontext(close_db)
    with app.app_context():
        init_db()
