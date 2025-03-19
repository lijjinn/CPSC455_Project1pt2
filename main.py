from flask import Flask, render_template, request, session, redirect, url_for, send_from_directory
from flask_socketio import join_room, leave_room, send, SocketIO
import random
import time
import re
import os
import datetime
from collections import defaultdict
from string import ascii_uppercase

app = Flask(__name__)
app.config["SECRET_KEY"] = "hjhjsdahhds"
app.config["UPLOAD_FOLDER"] = "uploads"  # Folder where uploaded files will be saved
socketio = SocketIO(app)

rooms = {}
user_message_times = defaultdict(list)

MESSAGE_LIMIT = 5
TIME_WINDOW = 10

# Chat log setup
LOGS_DIR = "chat_logs"
os.makedirs(LOGS_DIR, exist_ok=True)
os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)  # Create the upload folder if it doesn't exist

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

def get_log_filename(room):
    date_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    return f"chatlog_{room}_{date_str}.txt"

def log_message(room, name, message):
    log_file = get_log_filename(room)
    log_path = os.path.join(LOGS_DIR, log_file)

    timestamp = datetime.datetime.now().strftime("[%Y-%m-%d %H:%M:%S]")
    log_entry = f"{timestamp} {name}: {message}\n"

    with open(log_path, "a") as file:
        file.write(log_entry)

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

@app.route("/room", methods=["GET", "POST"])
def room():
    room = session.get("room")
    if not room or not session.get("name"):
        return redirect(url_for("home"))

    if request.method == "POST":
        # Handle file upload
        file = request.files.get("file")
        if file:
            # Save the file to the server
            filename = file.filename
            file.save(os.path.join(app.config["UPLOAD_FOLDER"], filename))

    # Get the list of files in the upload folder
    uploaded_files = os.listdir(app.config["UPLOAD_FOLDER"])
    return render_template("room.html", code=room, uploaded_files=uploaded_files)

@app.route("/uploads/<filename>")
def download_file(filename):
    # Serve the file for download
    return send_from_directory(app.config["UPLOAD_FOLDER"], filename)

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

