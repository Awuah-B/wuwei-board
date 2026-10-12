import functools
import hmac
import os
import re
import secrets
import sqlite3
from datetime import timedelta

import bcrypt
import click
from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)

app = Flask(__name__)
DATABASE = os.path.join(app.root_path, "board.db")


# ---------- Settings and secret key ----------

def load_secret_key():
    """Create a random key on first run and reuse it afterwards."""
    path = os.path.join(app.root_path, "secret.key")
    if not os.path.exists(path):
        with open(path, "wb") as f:
            f.write(secrets.token_bytes(32))
        os.chmod(path, 0o600)
    with open(path, "rb") as f:
        return f.read()


app.secret_key = load_secret_key()
app.config.update(
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    PERMANENT_SESSION_LIFETIME=timedelta(hours=8),
)

# Used so a wrong username takes as long to reject as a wrong password.
DUMMY_HASH = bcrypt.hashpw(b"dummy", bcrypt.gensalt())


# ---------- Database helpers ----------

def get_db():
    """Open one database connection per request and reuse it."""
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
        g.db.execute("PRAGMA foreign_keys = ON")
    return g.db


@app.teardown_appcontext
def close_db(error):
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


@app.cli.command("create-admin")
@click.option("--username", prompt=True)
@click.password_option()
def create_admin(username, password):
    """Create the admin account (or reset its password)."""
    if len(password) < 10 or len(password.encode()) > 72:
        raise click.ClickException("Password must be 10+ characters and at most 72 bytes.")
    hashed = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    db = get_db()
    db.execute("DELETE FROM admin")  # only one admin exists
    db.execute(
        "INSERT INTO admin (username, password_hash) VALUES (?, ?)",
        (username.strip(), hashed),
    )
    db.commit()
    click.echo("Admin saved.")


# ---------- Security helpers ----------

def csrf_token():
    if "csrf" not in session:
        session["csrf"] = secrets.token_hex(16)
    return session["csrf"]


app.jinja_env.globals["csrf_token"] = csrf_token


@app.before_request
def protect_admin_forms():
    """Every POST under /admin must carry the secret token."""
    if request.method == "POST" and request.path.startswith("/admin"):
        sent = request.form.get("csrf", "").encode()
        expected = session.get("csrf", "").encode()
        if not expected or not hmac.compare_digest(sent, expected):
            abort(400)


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("admin"):
            return redirect(url_for("login"))
        return view(*args, **kwargs)
    return wrapped


# ---------- Public pages ----------

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


# ---------- Admin: login ----------

@app.route("/admin/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "").encode()[:72]
        row = get_db().execute(
            "SELECT * FROM admin WHERE username = ?", (username,)
        ).fetchone()
        stored = row["password_hash"].encode() if row else DUMMY_HASH
        if bcrypt.checkpw(password, stored) and row is not None:
            session.clear()
            session["admin"] = True
            session.permanent = True
            return redirect(url_for("admin"))
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/admin/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------- Admin: boards ----------

@app.route("/admin")
@admin_required
def admin():
    boards = get_db().execute(
        "SELECT boards.*, "
        "(SELECT COUNT(*) FROM threads WHERE threads.board_id = boards.id) AS thread_count "
        "FROM boards ORDER BY sort_order, name"
    ).fetchall()
    return render_template("admin.html", boards=boards)


@app.route("/admin/boards", methods=["POST"])
@admin_required
def create_board():
    slug = request.form.get("slug", "").strip().lower()
    name = request.form.get("name", "").strip()[:60]
    description = request.form.get("description", "").strip()[:200]
    if not re.fullmatch(r"[a-z0-9-]{1,20}", slug) or not name:
        flash("Slug must be 1-20 letters, numbers or dashes, and a name is required.")
        return redirect(url_for("admin"))
    db = get_db()
    try:
        db.execute(
            "INSERT INTO boards (slug, name, description) VALUES (?, ?, ?)",
            (slug, name, description),
        )
        db.commit()
        flash(f"Board /{slug}/ created.")
    except sqlite3.IntegrityError:
        flash("That slug is already taken.")
    return redirect(url_for("admin"))


@app.route("/admin/boards/<int:board_id>/edit", methods=["POST"])
@admin_required
def edit_board(board_id):
    name = request.form.get("name", "").strip()[:60]
    description = request.form.get("description", "").strip()[:200]
    comments_enabled = 1 if request.form.get("comments_enabled") else 0
    try:
        sort_order = int(request.form.get("sort_order", "0"))
    except ValueError:
        sort_order = 0
    if not name:
        flash("A board needs a name.")
        return redirect(url_for("admin"))
    db = get_db()
    db.execute(
        "UPDATE boards SET name = ?, description = ?, comments_enabled = ?, "
        "sort_order = ? WHERE id = ?",
        (name, description, comments_enabled, sort_order, board_id),
    )
    db.commit()
    flash("Board saved.")
    return redirect(url_for("admin"))


@app.route("/admin/boards/<int:board_id>/delete", methods=["POST"])
@admin_required
def delete_board(board_id):
    db = get_db()
    board = db.execute("SELECT * FROM boards WHERE id = ?", (board_id,)).fetchone()
    if board is None:
        abort(404)
    if request.form.get("confirm", "").strip() != board["slug"]:
        flash("Confirmation did not match. Board not deleted.")
        return redirect(url_for("admin"))
    db.execute("DELETE FROM boards WHERE id = ?", (board_id,))
    db.commit()
    flash(f"Deleted /{board['slug']}/ and everything in it.")
    return redirect(url_for("admin"))
