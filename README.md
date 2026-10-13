# wuwei-board

A small Flask imageboard for short posts about what you are reading: title, comment, thumbnail, and an optional http(s) link (GitHub or anything else). You create threads as admin; visitors can reply if comments are enabled on the board.

## Setup

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
flask --app app init-db
flask --app app create-admin
flask --app app run
```

Open http://127.0.0.1:5000 and log in at `/admin`.

## Production

Use gunicorn behind HTTPS:

```bash
export SESSION_COOKIE_SECURE=1
gunicorn --bind 127.0.0.1:8000 app:app
```

`secret.key` is created on first run and must not be committed. `board.db` and `static/uploads/` are local data; back them up if you care about posts.
