from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from flask_socketio import join_room, leave_room, send, SocketIO
from flask_session import Session
import bcrypt
import random
import time
import re
import os
import json
import base64
from collections import defaultdict
from string import ascii_uppercase

app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdahhds"
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

socketio = SocketIO(app)

rooms = {}
user_message_times = defaultdict(list)

MESSAGE_LIMIT = 5
TIME_WINDOW = 10

LOGS_DIR = "chat_logs"
UPLOADS_DIR = "uploads"
USER_DB = "users.json"

# Ensure log and upload directories exist
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
if not os.path.exists(UPLOADS_DIR):
    os.makedirs(UPLOADS_DIR)

# Load and Save User Data
def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as file:
            return json.load(file)
    return {}

def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)

# Password Hashing and Verification
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def verify_password(password, hashed_password):
    return bcrypt.checkpw(password.encode('utf-8'), hashed_password.encode('utf-8'))

# Generate Unique Room Code
def generate_unique_code(length):
    while True:
        code = "".join(random.choice(ascii_uppercase) for _ in range(length))
        if code not in rooms:
            return code

# Message Formatting
def format_text(text):
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
    text = re.sub(r'\[([^\]]+)\]\((https?:\/\/[^\s]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
    return text

# Logging Messages
def log_message(room, name, message):
    log_file = os.path.join(LOGS_DIR, f"{room}.txt")
    with open(log_file, "a") as file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        file.write(f"[{timestamp}] {name}: {message}\n")

# Routes
@app.route("/", methods=["POST", "GET"])
def home():
    if "username" not in session:
        return redirect(url_for("login"))

    if request.method == "POST":
        name = session["username"]
        code = request.form.get("code")
        join = request.form.get("join")
        create = request.form.get("create")

        if create == "CreateRoom":
            room = generate_unique_code(4)
            rooms[room] = {"members": 1, "messages": []}
            session["room"] = room
            return redirect(url_for("room"))

        if join == "Join" and not code:
            return render_template("home.html", error="Please enter a room code.")

        if code not in rooms:
            return render_template("home.html", error="Room does not exist.")

        session["room"] = code
        return redirect(url_for("room"))

    return render_template("home.html")

@app.route("/register", methods=["POST", "GET"])
def register():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")

        # Load existing users
        users = load_users()

        # Prevent duplicate usernames
        if username in users:
            return render_template("register.html", error="User already exists.")

        # Hash and save the password securely
        hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        users[username] = hashed_password

        # Save back to users.json
        save_users(users)

        return redirect(url_for("login"))

    return render_template("register.html")



@app.route("/login", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        users = load_users()

        # Check if user exists and verify password
        if username not in users or not verify_password(password, users[username]):
            return render_template("login.html", error="Invalid credentials.")

        # Store user session
        session["username"] = username
        return redirect(url_for("home"))

    return render_template("login.html")



@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))

@app.route("/room")
def room():
    room = session.get("room")
    if not room or not session.get("username") or room not in rooms:
        return redirect(url_for("home"))

    return render_template("room.html", code=room, messages=rooms[room]["messages"])

# WebSocket Events
@socketio.on("message")
def message(data):
    room = session.get("room")
    name = session.get("username")
    if room not in rooms:
        return

    now = time.time()
    timestamps = user_message_times[name]

    timestamps = [t for t in timestamps if now - t < TIME_WINDOW]
    user_message_times[name] = timestamps

    if len(timestamps) >= MESSAGE_LIMIT:
        send({"name": "Server", "message": "Rate limit exceeded. Please wait a moment."}, to=room)
        return

    user_message_times[name].append(now)
    formatted_message = format_text(data["data"])
    content = {"name": name, "message": formatted_message}

    log_message(room, name, formatted_message)

    send(content, to=room)
    rooms[room]["messages"].append(content)

@socketio.on("connect")
def connect(auth):
    room = session.get("room")
    name = session.get("username")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return

    join_room(room)
    send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1

@socketio.on("disconnect")
def disconnect():
    room = session.get("room")
    name = session.get("username")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]

    send({"name": name, "message": "has left the room"}, to=room)

if __name__ == "__main__":
    socketio.run(app, debug=True)

