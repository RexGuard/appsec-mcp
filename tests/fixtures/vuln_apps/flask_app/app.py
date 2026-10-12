import sqlite3

import requests
from flask import Flask, render_template, request

app = Flask(__name__)
app.config["SECRET_KEY"] = "dev"


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/calc")
def calc():
    expression = request.args.get("expr", "1+1")
    return str(eval(expression))


@app.route("/profile", methods=["POST"])
def update_profile():
    email = request.form["email"]
    db = sqlite3.connect("app.db")
    db.execute("UPDATE users SET email = ? WHERE id = 1", (email,))
    db.commit()
    return "saved"


@app.route("/weather")
def weather():
    city = request.args.get("city", "Singapore")
    return requests.get("https://api.weather.example/v1", params={"q": city}, timeout=5).text


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
