from datetime import datetime
from cs50 import SQL
from flask import Flask, flash, redirect, render_template, request, session, jsonify
from flask_session import Session
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required

app = Flask(__name__)
app.debug = True

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

db = SQL("sqlite:///crown.db")

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/")
@login_required
def index():
    if request.method == "GET":

        username = db.execute("SELECT * FROM users WHERE id = ?", session["user_id"])[0]["username"]

        return render_template("index.html", username=username)


@app.route("/login", methods=["GET", "POST"])
def login():

    session.clear()

    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        if not username:
            return apology("Please input a valid username or email.")
        
        if not password:
            return apology("Please input a valid password.")
        
        if "@" in username:
            rows = db.execute(
                "SELECT * FROM users WHERE email = ?", username.lower().strip()
            )
        else:
            rows = db.execute(
                "SELECT * FROM users WHERE username = ?", username.lower().strip()
            )

        if len(rows) != 1 or not check_password_hash(
            rows[0]["hash"], password
        ):
            return apology("Your username or password is incorrect.")
    
        session["user_id"] = rows[0]["id"]

        return redirect("/")
    
    else:
        return render_template("login.html")
        
@app.route("/logout")
def logout():

    session.clear()

    return redirect("/")

@app.route("/register", methods=["GET", "POST"])
def register():

    if request.method == "POST":
        username = request.form.get("username").lower().strip()
        email = request.form.get("email").lower().strip()
        password = request.form.getlist("password")
        username_rows = db.execute("SELECT * FROM users WHERE username = ?", username)
        email_rows = db.execute("SELECT * FROM users WHERE email = ?", email)

        if not username:
            return apology("Please input a valid username.")
        
        if not email:
            return apology("Please input a valid email address.")
        
        if not password[0] or not password[1]:
            return apology("Please input a valid password.")
        
        if password[0] != password[1]:
            return apology("Please ensure passwords match eachother.")
        
        if len(username_rows) != 0:
            return apology("Username taken.")
        
        if len(email_rows) != 0:
            return apology("Email is already in use.")

        db.execute(
            "INSERT INTO users (username, email, hash) VALUES (?, ?, ?)", 
            username, email, generate_password_hash(password[0])
            )
        
        rows = db.execute("SELECT * FROM users WHERE username = ?", username)

        session["user_id"] = rows[0]["id"]

        return redirect("/")
    
    else:
        return render_template("register.html")
        
@app.route("/deregister", methods=["GET", "POST"])
@login_required
def deregister():

    if request.method == "POST":

        action = request.form.get('action')
        if action == 'return':
            return redirect("/")

        elif action == 'delete':
            db.execute("DELETE FROM users WHERE id = ?", session["user_id"])
            session.clear()
            return redirect("/")
    
    return render_template('deregister.html')

@app.route('/validate', methods=['POST'])
def validate():

    data = request.json
    print("Received data:", data)

    result = {'message': 'Action Triggered'}

    return jsonify(result)

if __name__ == "__main__":
    app.run(debug=True)