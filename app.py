from functools import wraps
import os
import time
from flask import Flask, flash, render_template, request, redirect, session, session, g, url_for
import mysql.connector
from werkzeug.security import generate_password_hash, check_password_hash
import logging
from logging.handlers import RotatingFileHandler
import validators

# Setup Flask app

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY")

app.config["RECAPTCHA_USE_SSL"] = False
app.config["RECAPTCHA_PUBLIC_KEY"] = os.environ.get("RECAPTCHA_PUBLIC_KEY") # Behöver tekniskt sett inte vara en miljövariabel men om någon ska skaffa en egen private key så är det smidigare att inte behöva ändra i koden
app.config["RECAPTCHA_PRIVATE_KEY"] = os.environ.get("RECAPTCHA_PRIVATE_KEY")

# Logging setup

def setup_logging():
    """
    Sets up logging for the application. Logs will be written to 'app.log' with a maximum size of 1MB and up to 10 backup files.
    """
    if not os.path.exists('logs'):
        os.mkdir('logs')
    handler = RotatingFileHandler('logs/app.log', maxBytes=1000000, backupCount=10)
    formatter = logging.Formatter('%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    app.logger.info('Logging setup complete')

@app.before_request
def start_timer():
    g.start_time = time.time()
    app.logger.info(f"Start: {request.method} {request.path}")

@app.after_request
def log_request(response):
    duration = time.time() - g.start_time
    app.logger.info(f"End: {request.method} {request.path} -> {response.status_code} in {duration:.4f}s")
    return response

# Decorators for authentication

def login_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Checking if user is logged in")
        if "user_id" not in session:
            print("User is not logged in, redirecting to login page")
            return redirect(url_for("login"))
        print(f"User {session['username']} with id {session['user_id']} is logged in, proceeding...")
        return func(*args, **kwargs)
    return wrapper

def logged_out_required(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        print("Checking if user is logged in")
        if "user_id" in session:
            print(f"User {session['username']} with id {session['user_id']} is logged in, redirecting to homepage")
            return redirect(url_for("index"))
        print(f"User is not logged in, proceeding...")
        return func(*args, **kwargs)
    return wrapper

# Database connection

def get_db_connection():
    return mysql.connector.connect(
        host='localhost',
        user='root',  
        password='',  
        database='archive'
    )

# Authentication functions

def create_user(username, email, password):
    validate_user_input(username, email, password)
    print(f"Creating user with username: {username}")
    hashed_password = generate_password_hash(password)
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (username, email, password) VALUES (%s, %s, %s)", (username, email, hashed_password))
    conn.commit()
    cursor.close()
    conn.close()
    print(f"User {username} created successfully")

def validate_user_input(username, email, password):

    # Several of these are already handled by HTML form validation, but we want to be sure and not rely on that (and some of them are not, like the allowed special characters in username)

    ALLOWED_USERNAME_SPECIALS = set("-_.")

    if not username or not email or not password:
        raise ValueError("All fields are required")
    
    if len(username) < 3 or len(username) > 20:
        raise ValueError("Username must be between 3 and 20 characters")
    
    if " " in username:
        raise ValueError("Username cannot contain spaces")
    
    username_without_allowed_specials = ''.join(c for c in username if c not in ALLOWED_USERNAME_SPECIALS)
    if not username_without_allowed_specials.isalnum():
        raise ValueError("Username can only contain letters, numbers, and the permitted special characters '-', '.' and '_'")
    
    if username_taken(username):
        # Will show this for UX reasons despite security risk. The Captcha should help guard against mass enumeration attacks if i implemented it correctly.
        raise ValueError("Username is already taken")

    if not validators.email(email):
        raise ValueError("Invalid email address")
    
    if email_taken(email):

        # Might change later to allow multiple accounts with the same email or just tell the user they'll be sent a verification email instead of raising an error

        raise ValueError("Email is already taken")

    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    
    if len(password) > 512:
        raise ValueError("Password cannot be longer than 512 characters")
    
def username_taken(username):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE username = %s", (username,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result is not None

def email_taken(email):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM users WHERE email = %s", (email,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result is not None

def authenticate_user(username, password):
    print(f"Authenticating user with username or email: {username}")
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM users WHERE username = %s OR email = %s", (username, username))
    user = cursor.fetchone()
    cursor.close()
    conn.close()

    if user and check_password_hash(user["password"], password):
        print(f"User {username} authenticated successfully")
        return user
    print(f"Authentication failed for user {username}")
    return None

# Misc functions

def alt_route_redirect(func_name):
    """Creates a function that redirects to the original endpoint. This is used for connecting alternative routes to the same endpoint without having to duplicate the code or use multiple route decorators on the same function (which can get messy and hard to read with many alternative routes).
    """
    return lambda: redirect(url_for(func_name))


def connect_alt_routes(func_name, *route_variations):
    """Connects multiple alternative routes to the same endpoint function. This allows users to access the same page using different URLs (e.g., /login, /log-in, /sign-in, etc.) without having to duplicate code or use multiple route decorators on the same function."""
    for route in route_variations:
        print(f"Connecting alternative route '{route}' to endpoint '{func_name}'")

        #Create a new function that redirects to the original endpoint and give it a unique name based on the route to avoid conflicts in Flask's routing system (It took me sooo long to figure out that the issue with the alternative routes not working was that they were all trying to use the same function name and thus overwriting each other in the routing system :,) )
        func = alt_route_redirect(func_name)
        func.__name__ = f"{func_name}_alt_{route.strip('/')}"
        print(f"Created redirect function '{func.__name__}' for route '{route}'") 
        app.add_url_rule(route, func.__name__, func)
    
# Routes

@app.route('/')
@login_required
def index():
    return render_template('index.html', username=session.get("username"))

connect_alt_routes("index", "/index", "/home")


@app.route("/login", methods=["GET", "POST"])
@logged_out_required
def login():
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]
        captcha_response = request.form["g-recaptcha-response"]

        if not captcha_response:
            flash("Please complete the CAPTCHA")
            return render_template("login.html")
        
        user = authenticate_user(username, password)

        if user:
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            return redirect(url_for("index"))
        
        flash("Invalid username or password")
        return redirect(url_for("login"))
    return render_template("login.html")

connect_alt_routes("login", "/log_in", "/log-in", "/sign_in", "/sign-in", "/signin")


@app.route("/register", methods=["GET", "POST"])
@logged_out_required
def register():
    if request.method == "POST":
        username = request.form["username"]
        email = request.form["email"]
        password = request.form["password"]
        confirm_password = request.form["confirm_password"]
        captcha_response = request.form["g-recaptcha-response"]

        if not captcha_response:
            flash("Please complete the CAPTCHA")
            return render_template("register.html")

        if password != confirm_password:
            flash("Passwords do not match")
            return render_template("register.html")

        try:
            create_user(username, email, password)
        except ValueError as e:
            flash(str(e))
            return render_template("register.html")
        return redirect(url_for("login"))
    return render_template("register.html")

connect_alt_routes("register", "/sign_up", "/signup", "/sign-up")


@app.route("/logout")
@login_required
def logout():
    session.clear()
    return redirect(url_for("login"))

connect_alt_routes("logout", "/log_out", "/log-out")

if __name__ == '__main__':
    setup_logging()
    app.run(debug=True)