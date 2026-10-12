import os
import sqlite3

import click

from flask import Flask, g, render_template

app = Flask(__name__)
DATABASE = os.path.join(app.root_path, "board.db")

def get_db():
    """Open one database connection per request and reuse it."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db

@app.teardown_appcontext
def close_db(error):
    """Close the connection when the request ends."""
    db = g.pop("db", None)
    if db is not None:
        db.close()

@app.cli.command("init-db")
def init_db():
    """Create the tables from schema.sql. """
    db = get_db()
    with open(os.path.join(app.root_path, "schema.sql")) as f:
        db.executescript(f.read())
    db.commit()
    click.echo("Database ready.")

@app.route("/")
def home():
    boards = get_db().execute(
        "SELECT * FROM boards ORDER BY sort_order, name"
            ).fetchall()
    return render_template("home.html", boards=boards)
