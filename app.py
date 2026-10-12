import os
import sqlite3

import click
from flask import Flask, abort, g, redirect, render_template, request, url_for

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
    """Create the tables from schema.sql."""
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
    db = get_db()
    thread = db.execute(
        "SELECT threads.*, boards.slug AS board_slug, boards.name AS board_name, "
        "boards.comments_enabled AS comments_enabled "
        "FROM threads JOIN boards ON boards.id = threads.board_id "
        "WHERE threads.id = ?",
        (thread_id,),
    ).fetchone()
    if thread is None:
        abort(404)

    posts = db.execute(
        "SELECT * FROM posts WHERE thread_id = ? ORDER BY id",
        (thread_id,),
    ).fetchall()
    return render_template("thread.html", thread=thread, posts=posts)


@app.route("/thread/<int:thread_id>/reply", methods=["POST"])
def reply(thread_id):
    db = get_db()
    thread = db.execute(
        "SELECT threads.id, threads.locked, boards.comments_enabled "
        "FROM threads JOIN boards ON boards.id = threads.board_id "
        "WHERE threads.id = ?",
        (thread_id,),
    ).fetchone()
    if thread is None:
        abort(404)
    if thread["locked"] or not thread["comments_enabled"]:
        abort(403)

    name = request.form.get("name", "").strip()[:30] or "Anonymous"
    body = request.form.get("body", "").strip()
    if not body or len(body) > 2000:
        abort(400)

    cur = db.execute(
        "INSERT INTO posts (thread_id, name, body) VALUES (?, ?, ?)",
        (thread_id, name, body),
    )
    db.execute(
        "UPDATE threads SET last_activity_at = CURRENT_TIMESTAMP WHERE id = ?",
        (thread_id,),
    )
    db.commit()
    return redirect(url_for("thread", thread_id=thread_id) + f"#p{cur.lastrowid}")
