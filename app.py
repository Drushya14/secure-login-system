from flask import Flask, render_template, request, redirect, url_for, session
import sqlite3
import bcrypt
import os
app = Flask(__name__)

# Secret key for secure sessions
app.secret_key = os.environ.get("SECRET_KEY","development-key")


# Create database and users table
def init_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    """)

    conn.commit()
    conn.close()


# Home page
@app.route("/")
def home():
    if "username" in session:
        return redirect(url_for("dashboard"))

    return redirect(url_for("login"))


# Registration
@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        # Input validation
        if len(username) < 3:
            return "Username must contain at least 3 characters."

        if len(password) < 8:
            return "Password must contain at least 8 characters."

        # Hash password
        hashed_password = bcrypt.hashpw(
            password.encode("utf-8"),
            bcrypt.gensalt()
        )

        try:
            conn = sqlite3.connect("users.db")
            cursor = conn.cursor()

            cursor.execute(
                "INSERT INTO users (username, password) VALUES (?, ?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            return redirect(url_for("login"))

        except sqlite3.IntegrityError:
            return "Username already exists."

    return render_template("register.html")


# Login
@app.route("/login", methods=["GET", "POST"])
def login():

    if request.method == "POST":
        username = request.form["username"].strip()
        password = request.form["password"]

        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()

        cursor.execute(
            "SELECT id, username, password FROM users WHERE username = ?",
            (username,)
        )

        user = cursor.fetchone()
        conn.close()

        if user:
            stored_password = user[2]

            if bcrypt.checkpw(
                password.encode("utf-8"),
                stored_password
            ):
                session["user_id"] = user[0]
                session["username"] = user[1]

                return redirect(url_for("dashboard"))

        return "Invalid username or password."

    return render_template("login.html")


# Dashboard
@app.route("/dashboard")
def dashboard():

    if "username" not in session:
        return redirect(url_for("login"))

    return render_template(
        "dashboard.html",
        username=session["username"]
    )


# Logout
@app.route("/logout")
def logout():

    session.clear()

    return redirect(url_for("login"))
init_db()

if __name__ == "__main__":
    app.run(debug=True)