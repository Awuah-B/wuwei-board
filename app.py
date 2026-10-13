import functools
import hmac
import os
import re
import secrets
import sqlite3
import time
import threading
from collections import defaultdict
from datetime import timedelta

import bcrypt
import click
from flask import Flask, abort, flash, g, redirect, render_template, request, session, url_for
from markupsafe import Markup, escape
from PIL import Image
from werkzeug.middleware.proxy_fix import ProxyFix

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

DATABASE = os.path.join(app.root_path, "board.db")

# ---------- Upload config ----------
UPLOAD_FOLDER = os.path.join(app.root_path, "static", "uploads")
THUMB_FOLDER = os.path.join(app.root_path, "static", "thumbs")
ALLOWED_EXTENSIONS = {"png", "jpg", "jpeg", "gif", "webp"}
MAX_CONTENT_LENGTH = 4 * 1024 * 1024  # 4 MB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH
app.config["DONATION_BTC_ADDRESS"] = "bc1qg8m4slzxzafqvxwvuq3n42u7wrzdwpctpz4za0"
def ensure_dirs():
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    os.makedirs(THUMB_FOLDER, exist_ok=True)

ensure_dirs()

def allowed_file(filename):
    return "." in filename and filename.rsplit(".", 1)[1].lower() in ALLOWED_EXTENSIONS

def save_upload(file_storage):
    """
    Validate, re-encode (strips metadata), and reject unreadable images.
    """
    if file_storage is None or not file_storage.filename:
        return None
    
    if not allowed_file(file_storage.filename):
        return None
    
    ext = file_storage.filename.rsplit(".", 1)[1].lower()
    fname = secrets.token_hex(8) + "." + ext
    
    try:
        # 1. Validate by opening with PIL (rejects unreadable/malformed files)
        img = Image.open(file_storage)
        img.verify()
        
        # 2. Re-open because verify() consumes the stream
        file_storage.seek(0)
        img = Image.open(file_storage)
        
        # 3. Convert to RGB to strip alpha channels/metadata issues and standardize
        if img.mode in ("RGBA", "P", "LA"):
            img = img.convert("RGB")
            fname = fname.rsplit(".", 1)[0] + ".jpg"
        
        filepath = os.path.join(UPLOAD_FOLDER, fname)
        
        # 4. Save with optimization (strips EXIF/metadata)
        img.save(filepath, optimize=True, quality=85)
        
        # 5. Generate thumbnail
        img.thumbnail((250, 250))
        thumb_path = os.path.join(THUMB_FOLDER, fname)
        img.save(thumb_path, optimize=True, quality=85)
        
    except Exception as e:
        # Reject anything unreadable or invalid
        print(f"Image validation/save failed: {e}")
        return None
        
    return fname

def delete_upload(filename):
    """Delete an uploaded file and its thumbnail."""
    if not filename:
        return
    for folder in (UPLOAD_FOLDER, THUMB_FOLDER):
        path = os.path.join(folder, filename)
        if os.path.exists(path):
            os.remove(path)
    
    # Also try .jpg thumb variant for converted PNGs
    base = filename.rsplit(".", 1)[0]
    jpg_thumb = os.path.join(THUMB_FOLDER, base + ".jpg")
    if os.path.exists(jpg_thumb):
        os.remove(jpg_thumb)

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
    SESSION_COOKIE_SECURE=(os.environ.get("FLASK_ENV") == "production"),
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

# ---------- Post formatting ----------
def format_post(text):
    """Format post text with greentext and quotelinks."""
    text = str(escape(text))
    # Replace &gt;&gt;number with clickable quotelinks (escaped >)
    text = re.sub(
        r'&gt;&gt;(\d+)',
        r'<a href="#p\1" class="quotelink">&gt;&gt;\1</a>',
        text,
    )
    # Process lines for greentext
    lines = text.split("\n")
    result = []
    for line in lines:
        # Check for escaped > but not >>
        if line.startswith("&gt;") and not line.startswith("&gt;&gt;"):
            line = f'<span class="greentext">{line}</span>'
        result.append(line)
    return Markup("<br>".join(result))

app.jinja_env.filters["format_post"] = format_post

# ---------- Security helpers ----------
@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        "img-src 'self' data:; "
        "style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline';"
    )
    return response

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

# ---------- Rate Limiting (Dependency-Free) ----------
_upload_rate_limit = defaultdict(list)
_rate_limit_lock = threading.Lock()

def rate_limit_uploads(max_requests=5, window_seconds=60):
    def decorator(f):
        @functools.wraps(f)
        def wrapped(*args, **kwargs):
            ip = request.headers.get("X-Forwarded-For", request.remote_addr)
            if ip:
                ip = ip.split(",")[0].strip()
            
            now = time.time()
            with _rate_limit_lock:
                # Clean old entries
                _upload_rate_limit[ip] = [t for t in _upload_rate_limit[ip] if now - t < window_seconds]
                if len(_upload_rate_limit[ip]) >= max_requests:
                    abort(429, "Rate limit exceeded. Please wait before uploading again.")
                _upload_rate_limit[ip].append(now)
            return f(*args, **kwargs)
        return wrapped
    return decorator

# ---------- Jinja helpers ----------
def thumb_filename(filename):
    """Get the thumbnail filename (may be .jpg for converted PNGs)."""
    if not filename:
        return None
    base, ext = filename.rsplit(".", 1)
    if os.path.exists(os.path.join(THUMB_FOLDER, filename)):
        return filename
    jpg = base + ".jpg"
    if os.path.exists(os.path.join(THUMB_FOLDER, jpg)):
        return jpg
    return filename

app.jinja_env.globals["thumb_filename"] = thumb_filename

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
        "SELECT threads.*, "
        "(SELECT COUNT(*) FROM posts WHERE posts.thread_id = threads.id) AS reply_count "
        "FROM threads WHERE board_id = ? "
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
@rate_limit_uploads(max_requests=5, window_seconds=60)
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
    
    # 1. TEXT VALIDATION FIRST (before processing images)
    name = request.form.get("name", "").strip()[:30] or "Anonymous"
    body = request.form.get("body", "").strip()
    
    if len(body) > 2000:
        abort(400)
        
    file = request.files.get("file")
    
    # 2. IMAGE SAVE (only after text is validated)
    image_filename = save_upload(file)
    
    if not body and not image_filename:
        abort(400)
        
    cur = db.execute(
        "INSERT INTO posts (thread_id, name, body, image_filename) VALUES (?, ?, ?, ?)",
        (thread_id, name, body, image_filename),
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
    quote = request.form.get("quote", "").strip()[:200]
    if not re.fullmatch(r"^[a-z0-9-]{1,20}$", slug) or not name:
        flash("Slug must be 1-20 letters, numbers or dashes, and a name is required.")
        return redirect(url_for("admin"))
    db = get_db()
    try:
        db.execute(
            "INSERT INTO boards (slug, name, description) VALUES (?, ?, ?)",
            (slug, name, description, quote),
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
    quote = request.form.get("quote", "").strip()[:200]
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
    
    # Clean up uploaded images
    threads = db.execute("SELECT id, image_filename FROM threads WHERE board_id = ?", (board_id,)).fetchall()
    for t in threads:
        delete_upload(t["image_filename"])
        posts = db.execute("SELECT image_filename FROM posts WHERE thread_id = ?", (t["id"],)).fetchall()
        for p in posts:
            delete_upload(p["image_filename"])
            
    db.execute("DELETE FROM boards WHERE id = ?", (board_id,))
    db.commit()
    flash(f"Deleted /{board['slug']}/ and everything in it.")
    return redirect(url_for("admin"))

# ---------- Admin: threads ----------
@app.route("/admin/boards/<int:board_id>/threads")
@admin_required
def admin_threads(board_id):
    db = get_db()
    board = db.execute("SELECT * FROM boards WHERE id = ?", (board_id,)).fetchone()
    if board is None:
        abort(404)
    threads = db.execute(
        "SELECT threads.*, "
        "(SELECT COUNT(*) FROM posts WHERE posts.thread_id = threads.id) AS reply_count "
        "FROM threads WHERE board_id = ? "
        "ORDER BY pinned DESC, last_activity_at DESC",
        (board_id,),
    ).fetchall()
    return render_template("admin_threads.html", board=board, threads=threads)

@app.route("/admin/threads", methods=["POST"])
@rate_limit_uploads(max_requests=5, window_seconds=60)
@admin_required
def create_thread():
    board_id = request.form.get("board_id", type=int)
    if not board_id:
        abort(400)
    db = get_db()
    board = db.execute("SELECT * FROM boards WHERE id = ?", (board_id,)).fetchone()
    if board is None:
        abort(404)
    
    # 1. TEXT VALIDATION FIRST
    title = request.form.get("title", "").strip()[:100]
    name = request.form.get("name", "").strip()[:30] or "Anonymous"
    body = request.form.get("body", "").strip()[:5000]
    status = request.form.get("status", "Active").strip()
    
    if status not in ("Active", "In progress", "Completed", "Archived"):
        status = "Active"
        
    if not title or not body:
        flash("Title and body are required.")
        return redirect(url_for("admin_threads", board_id=board_id))
        
    # 2. IMAGE SAVE (only after text is validated)
    file = request.files.get("file")
    image_filename = save_upload(file)
    
    db.execute(
        "INSERT INTO threads (board_id, title, name, body, image_filename, status) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (board_id, title, name, body, image_filename, status),
    )
    db.commit()
    flash(f"Thread \"{title}\" created.")
    return redirect(url_for("admin_threads", board_id=board_id))

@app.route("/admin/threads/<int:thread_id>/edit", methods=["POST"])
@admin_required
def edit_thread(thread_id):
    db = get_db()
    thread = db.execute("SELECT * FROM threads WHERE id = ?", (thread_id,)).fetchone()
    if thread is None:
        abort(404)
    
    title = request.form.get("title", "").strip()[:100]
    body = request.form.get("body", "").strip()[:5000]
    status = request.form.get("status", "Active").strip()
    
    if status not in ("Active", "In progress", "Completed", "Archived"):
        status = "Active"
        
    pinned = 1 if request.form.get("pinned") else 0
    locked = 1 if request.form.get("locked") else 0
    
    if not title:
        flash("Title is required.")
        return redirect(url_for("admin_threads", board_id=thread["board_id"]))
        
    db.execute(
        "UPDATE threads SET title = ?, body = ?, status = ?, pinned = ?, locked = ? "
        "WHERE id = ?",
        (title, body, status, pinned, locked, thread_id),
    )
    db.commit()
    flash("Thread updated.")
    return redirect(url_for("admin_threads", board_id=thread["board_id"]))

@app.route("/admin/threads/<int:thread_id>/delete", methods=["POST"])
@admin_required
def delete_thread(thread_id):
    db = get_db()
    thread = db.execute("SELECT * FROM threads WHERE id = ?", (thread_id,)).fetchone()
    if thread is None:
        abort(404)
    
    # Clean up images
    delete_upload(thread["image_filename"])
    posts = db.execute("SELECT image_filename FROM posts WHERE thread_id = ?", (thread_id,)).fetchall()
    for p in posts:
        delete_upload(p["image_filename"])
        
    db.execute("DELETE FROM threads WHERE id = ?", (thread_id,))
    db.commit()
    flash("Thread deleted.")
    return redirect(url_for("admin_threads", board_id=thread["board_id"]))

@app.route("/admin/posts/<int:post_id>/delete", methods=["POST"])
@admin_required
def delete_post(post_id):
    db = get_db()
    post = db.execute("SELECT * FROM posts WHERE id = ?", (post_id,)).fetchone()
    if post is None:
        abort(404)
    
    delete_upload(post["image_filename"])
    thread_id = post["thread_id"]
    
    db.execute("DELETE FROM posts WHERE id = ?", (post_id,))
    db.commit()
    flash("Post deleted.")
    return redirect(url_for("thread", thread_id=thread_id))
