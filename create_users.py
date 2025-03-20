import bcrypt
import json
import os

USER_DB = "users.json"

# Load existing users
def load_users():
    if os.path.exists(USER_DB):
        with open(USER_DB, "r") as file:
            return json.load(file)
    return {}

# Save new user
def save_users(users):
    with open(USER_DB, "w") as file:
        json.dump(users, file, indent=4)

# Generate a hashed password
def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

# Add a new user
def add_user(username, password):
    users = load_users()
    if username in users:
        print(f"❌ Username '{username}' already exists.")
        return
    
    users[username] = hash_password(password)
    save_users(users)
    print(f"✅ User '{username}' added successfully.")

# Add new users here
if __name__ == "__main__":
    add_user("john_doe", "securepassword123")
    add_user("jane_smith", "mypassword456")
    add_user("admin_user", "adminsecure789")
