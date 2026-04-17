import json

import bleach
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
    
    if username.isdigit():
        raise ValueError("Username cannot be entirely numeric")
    
    if username_taken(username):
        # Will show this for UX reasons despite security risk. The Captcha should help guard against mass enumeration attacks if I implemented it correctly.
        raise ValueError("Username is already taken")

    if len(email) > 64:
        raise ValueError("Email cannot be longer than 64 characters")

    if not validators.email(email):
        raise ValueError("Invalid email address")
    
    if email_taken(email):

        # Might change later to allow multiple accounts with the same email or just tell the user they'll be sent a verification email instead of raising an error

        raise ValueError("Email is already taken")

    if len(password) < 12:
        raise ValueError("Password must be at least 12 characters long")
    
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

# Misc functions

def alt_route_redirect(func_name):
    """Creates a function that redirects to the original endpoint. This is used for connecting alternative routes to the same endpoint without having to duplicate the code or use multiple route decorators on the same function (which can get messy and hard to read with many alternative routes).
    """
    return lambda: redirect(url_for(func_name))


def connect_alt_routes(func_name, *route_variations):
    """Connects multiple alternative routes to the same endpoint function. This allows users to access the same page using different URLs (e.g., /login, /log-in, /sign-in, etc.) without having to duplicate code or use multiple route decorators on the same function."""
    for route in route_variations:
        #Create a new function that redirects to the original endpoint and give it a unique name based on the route to avoid conflicts in Flask's routing system (It took me sooo long to figure out that the issue with the alternative routes not working was that they were all trying to use the same function name and thus overwriting each other in the routing system :,) )
        func = alt_route_redirect(func_name)
        func.__name__ = f"{func_name}_alt_{route.strip('/')}"
        app.add_url_rule(route, func.__name__, func)

# Post logic

def validate_post_input(title, content, tags=[]):
    if not title and not content:
        raise ValueError("Title and content cannot both be empty")
    
    if len(title) > 127:
        raise ValueError("Title cannot be longer than 127 characters")
    
    if len(content) > 2047:
        raise ValueError("Content cannot be longer than 2047 characters")
    
    for tag in tags:
        if len(tag) > 63:
            raise ValueError("Tags cannot be longer than 63 characters")
        if not tag.strip():
            raise ValueError("Tags cannot be empty or just whitespace")
    
    if len("".join(tags)) > 2047:
        raise ValueError("Combined length of all tags cannot exceed 2047 characters")
    
    
def sanitize_content(content):
    allowed_tags = ['b', 'i', 'u', 'em', 'strong', 'a']
    allowed_attributes = {'a': ['href', 'title', 'target']}
    cleaned_content = bleach.clean(content, tags=allowed_tags, attributes=allowed_attributes)
    return cleaned_content

def sanitize_tags(tags):
    bleached_tags = [bleach.clean(tag, tags=[], attributes={}) for tag in tags]
    return bleached_tags
    
def get_user_posts(user_id):
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT id, title, content, tags FROM posts WHERE poster_id = %s ORDER BY id DESC", (user_id,))
    posts = cursor.fetchall()

    posts = [dict(post, tags=json.loads(post["tags"]) if post["tags"] else []) for post in posts]
    print(posts)

    cursor.close()
    conn.close()
    return posts

def get_tag_posts(tag_name=None, tag_id=None):
    if not tag_name and not tag_id:
        raise ValueError("Either tag_name or tag_id must be provided")
    
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    #This query:
    # 1. Selects relevant post information (ID, title, content, tags) along with the username of the poster.
    # 2. Joins the posts table with the post_tags table to link posts to their tags.
    # 3. Joins the tags table to filter posts by the specified tag name.
    # 4. Joins the users table to get the username of the poster for each post.

    query = """SELECT posts.id, posts.title, posts.content, posts.tags, users.username FROM posts
    JOIN post_tags ON posts.id = post_tags.post_id 
    JOIN tags ON post_tags.tag_id = tags.id 
    JOIN users ON posts.poster_id = users.id"""

    # The WHERE clause depends on what information is provided

    if tag_name:
        query += " WHERE tags.name = %s ORDER BY posts.id DESC"
        cursor.execute(query, (tag_name,))
    
    else:
        query += " WHERE tags.id = %s ORDER BY posts.id DESC"
        cursor.execute(query, (tag_id,))
    
    posts = cursor.fetchall()
    posts = [dict(post, tags=json.loads(post["tags"]) if post["tags"] else []) for post in posts]
    return posts

def get_all_posts():
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT posts.id, posts.title, posts.content, posts.tags, users.username FROM posts JOIN users ON posts.poster_id = users.id ORDER BY posts.id DESC")
    posts = cursor.fetchall()
    cursor.close()
    conn.close()

    posts = [dict(post, tags=json.loads(post["tags"]) if post["tags"] else []) for post in posts]

    return posts

def get_tag_id(tag):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM tags WHERE name = %s", (tag,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None

def get_tag_name(tag_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT name FROM tags WHERE id = %s", (tag_id,))
    result = cursor.fetchone()
    cursor.close()
    conn.close()
    return result[0] if result else None

# Routes

@app.route('/')
@login_required
def index():
    return render_template('index.html', posts=get_all_posts())

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


@app.route("/delete-account", methods=["POST"])
@login_required
def delete_account():
    user_id = session.get("user_id")
    password = request.form.get("password", "")

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT * FROM users WHERE id = %s", (user_id,))
    user = cursor.fetchone()
    if not user:
        cursor.close()
        conn.close()
        flash("User not found, contact support")
        return redirect(url_for("profile"))
    if check_password_hash(user["password"], password):
        cursor.execute("DELETE FROM users WHERE id = %s", (user_id,))
        conn.commit()
        cursor.close()
        conn.close()
        session.clear()
        return redirect(url_for("register"))
    
    cursor.close()
    conn.close()
    flash("Incorrect password")
    return redirect(url_for("profile"))

@app.route("/profile")
@login_required
def profile():
    return render_template("profile.html")

connect_alt_routes("profile", "/my-profile", "/my_profile", "/user-profile", "/user_profile")

@app.route("/collections/<target_user>")
@login_required
def collections(target_user):
    conn = get_db_connection()
    cursor = conn.cursor()
    user = None

    if target_user.isdigit():
        target_user_id = int(target_user)
        cursor.execute("SELECT username FROM users WHERE id = %s", (target_user_id,))
        target_username = cursor.fetchone()
        if target_username:
            user = {"username": target_username[0],
                    "user_id": target_user_id}
    
    else:
        cursor.execute("SELECT id FROM users WHERE username = %s", (target_user,))
        target_user_id = cursor.fetchone()
        if target_user_id:
            user = {"username": target_user, 
                    "user_id": target_user_id[0]}
    
    if not user:
        cursor.close()
        conn.close()
        return redirect(url_for("index"))

    return render_template("user-page.html", user=user, posts=get_user_posts(user["user_id"]))

connect_alt_routes("my_page", "/user-page", "/user_page", "/my_page")

@app.route("/my-page")
@login_required
def my_page():
    return redirect(url_for("collections", target_user=session["user_id"]))

@app.route("/create-post", methods=["POST"])
@login_required
def create_post():
    title = request.form.get("title", "")
    content = request.form.get("content", "")
    tags = request.form.get("tags")
    tags = json.loads(tags) if tags else []
    print(f"Received new post with title: {title}, content: {content}, tags: {tags} from user_id: {session['user_id']}")

    # Validation and sanitization

    if not title or not content:
        flash("Title and content cannot be empty")
        return redirect(url_for("my_page"))
    
    try:
        validate_post_input(title, content, tags)
    except ValueError as e:
        flash(str(e))
        return redirect(url_for("my_page"))
    
    title = sanitize_content(title)
    content = sanitize_content(content)
    tags = sanitize_tags(tags)
    
    # DB operations

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)

    # Storing the main post data

    if tags:
        # We store the tags as a JSON array in the posts table to keep capitalization for display purposes, but they will also be stored in the tags table later for searching and filtering purposes.
        cursor.execute("INSERT INTO posts (poster_id, title, content, tags) VALUES (%s, %s, %s, %s)", (session["user_id"], title, content, json.dumps(tags)))
    else:
        cursor.execute("INSERT INTO posts (poster_id, title, content) VALUES (%s, %s, %s)", (session["user_id"], title, content))

    # Getting the ID of the newly created post to associate with tags
    cursor.execute("SELECT LAST_INSERT_ID() AS post_id")
    post_id = cursor.fetchone()["post_id"]

    # Storing tags if provided
    if tags:
        try:
            # Preparing the tags for database insertion. Has to be done before loop to catch new duplicates. (Tex: Tag1 and tag1 would now be considered duplicates)

            tags = [tag.strip() for tag in tags if tag.strip()]  # Remove leading/trailing whitespace and empty tags
            tags = [tag.lower() for tag in tags]  # Convert to lowercase for case-insensitive handling
            tags = list(set(tags))  # Remove duplicates while preserving order

            for tag in tags:
                print(f"Processing tag: {tag} for post_id: {post_id}")
                tag_id = get_tag_id(tag)
                if not tag_id:
                    cursor.execute("INSERT INTO tags (name) VALUES (%s)", (tag,))
                    tag_id = cursor.lastrowid

                cursor.execute("INSERT INTO post_tags (post_id, tag_id) VALUES (%s, %s)", (post_id, tag_id))
        except Exception as e:
            app.logger.error(f"Error while inserting tags for post_id {post_id}: {e}")

    conn.commit()
    cursor.close()
    conn.close()
        
    return redirect(url_for("my_page"))

@app.route("/tag/<tag_name>")
@login_required
def view_tag(tag_name):
    posts = get_tag_posts(tag_name.lower())
    return render_template("tag-page.html", posts=posts, tag_name=tag_name)


if __name__ == '__main__':
    setup_logging()
    app.run(debug=True)