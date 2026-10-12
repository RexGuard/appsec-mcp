import sqlite3

from flask import Flask, request

app = Flask(__name__)


def get_db():
    return sqlite3.connect("app.db")


@app.route("/calc")
def calc():
    expr = request.args.get("expr", "1+1")
    return str(eval(expr))


@app.route("/comment", methods=["POST"])
def comment():
    body = request.form["body"]
    db = get_db()
    db.execute("INSERT INTO comments (body) VALUES (?)", (body,))
    db.commit()
    return "ok"


@app.route("/user")
def user():
    name = request.args.get("name", "")
    cur = get_db().cursor()
    cur.execute(f"SELECT * FROM users WHERE name = '{name}'")
    return str(cur.fetchall())


if __name__ == "__main__":
    app.run(debug=True)
