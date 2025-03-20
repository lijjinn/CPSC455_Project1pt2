from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from flask_socketio import join_room, leave_room, send, SocketIO
import random
import time
import re
import os
import base64  # For file handling
from collections import defaultdict
from string import ascii_uppercase

app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdahhds"
socketio = SocketIO(app)

rooms = {}
user_message_times = defaultdict(list)

MESSAGE_LIMIT = 5
TIME_WINDOW = 10

LOGS_DIR = "chat_logs"
UPLOADS_DIR = "uploads"

# Ensure log and upload directories exist
if not os.path.exists(LOGS_DIR):
    os.makedirs(LOGS_DIR)
if not os.path.exists(UPLOADS_DIR):
    os.makedirs(UPLOADS_DIR)

def generate_unique_code(length):
    while True:
        code = "".join(random.choice(ascii_uppercase) for _ in range(length))
        if code not in rooms:
            return code

def format_text(text):
    text = re.sub(r'\*\*(.*?)\*\*', r'<strong>\1</strong>', text)
    text = re.sub(r'\*(.*?)\*', r'<em>\1</em>', text)
    text = re.sub(r'\[([^\]]+)\]\((https?:\/\/[^\s]+)\)', r'<a href="\2" target="_blank">\1</a>', text)
    return text

def log_message(room, name, message):
    log_file = os.path.join(LOGS_DIR, f"{room}.txt")
    with open(log_file, "a") as file:
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
        file.write(f"[{timestamp}] {name}: {message}\n")
    print(f"Logging message: {room} - {name}: {message}")

@app.route("/", methods=["POST", "GET"])
def home():
    session.clear()
    if request.method == "POST":
        name = request.form.get("name")
        code = request.form.get("code")
        join = request.form.get("join")
        create = request.form.get("create")

        if not name:
            return render_template("home.html", error="Please enter a name.", code=code, name=name)

        if join == "Join" and not code:
            return render_template("home.html", error="Please enter a room code.", code=code, name=name)

        if create == "CreateRoom":
            room = generate_unique_code(4)
            rooms[room] = {"members": 1, "messages": []}
            session["room"] = room
            session["name"] = name
            return redirect(url_for("room"))

        if code not in rooms:
            return render_template("home.html", error="Room does not exist.", code=code, name=name)

        session["room"] = code
        session["name"] = name
        return redirect(url_for("room"))

    return render_template("home.html")

@app.route("/room")
def room():
    room = session.get("room")
    if not room or not session.get("name") or room not in rooms:
        return redirect(url_for("home"))

    return render_template("room.html", code=room, messages=rooms[room]["messages"])

@socketio.on("file_upload")
def handle_file_upload(data):
    room = session.get("room")
    name = session.get("name")

    if not room or room not in rooms:
        return

    file_name = data["file_name"]
    file_data = data["file_data"]

    file_path = os.path.join(UPLOADS_DIR, file_name)

    # Decode and save the file
    with open(file_path, "wb") as f:
        f.write(base64.b64decode(file_data.split(",")[1]))

    socketio.emit("file_received", {
        "name": name,
        "file_name": file_name,
        "file_data": f"/uploads/{file_name}"
    }, room=room)

@app.route("/uploads/<filename>")
def download_file(filename):
    return send_from_directory(UPLOADS_DIR, filename)

@socketio.on("message")
def message(data):
    room = session.get("room")
    name = session.get("name")
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
    name = session.get("name")
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
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]

    send({"name": name, "message": "has left the room"}, to=room)

if __name__ == "__main__":
    socketio.run(app, debug=True)
