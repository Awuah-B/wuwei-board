from flask import Flask, render_template

app = Flask(__name__)

BOARDS = [
    {"slug": "income", "name": "Income Generation",
     "description": "Ways I'm trying to earn, and how it's going."},

    {"slug": "politics", "name": "Politics",
     "description": "Political topics I want to talk about."},        ]

@app.route("/")
def home():
    return render_template("home.html", boards=BOARDS)
