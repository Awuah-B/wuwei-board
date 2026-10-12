import os
import sqlite3

import click

from flask import Flask, abort, g, render_template

app = Flask(__name__)
DATABASE = os.path.join(app.root_path, "board.db")

def get_db():
    """Open one database connection per request and reuse it."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
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

@app.route("/b/<slug>")
def board(slug):
    db = get_db()
    board = db.execute(
                "SELECT * FROM boards WHERE slug = ?", (slug,)
            ).fetchone()
    if board is None:
        abort(404)

    threads = db.execute(
            "SELECT * FROM threads WHERE board_id = ? "
            "ORDER BY pinned DESC, last_activity_at DESC",
            (board["id"],),
            ).fetchall()

    return render_template("board.html", board=board, threads=threads)

@app.route("/thread/<int:thread_id>")
def thread(thread_id):
    thread = get_db().execute(
        "SELECT threads.*, boards.slug AS board_slug, boards.name AS board_name "
        "FROM threads JOIN boards ON boards.id = threads.board_id "
        "WHERE threads.id = ?",
        (thread_id,),
            ).fetchone()
    if thread is None:
        abort(404)
    return render_template("thread.html", thread=thread)
