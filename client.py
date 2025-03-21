import requests
from encryption_utils import encrypt_aes_key, aes_encrypt, aes_decrypt
import os
import socketio
import base64
from cryptography.hazmat.primitives import serialization

SERVER_URL = "http://localhost:5000"

# Step 1: Fetch public key
response = requests.get(f"{SERVER_URL}/get_public_key")
public_key_pem = response.content

# Step 2: Encrypt AES-256 key with RSA public key
aes_key = os.urandom(32)  # Generate a 32-byte AES key
encrypted_aes_key = encrypt_aes_key(aes_key, serialization.load_pem_public_key(public_key_pem))

# Step 3: Send encrypted AES key to the server
response = requests.post(f"{SERVER_URL}/exchange_key", json={"key": encrypted_aes_key})

if response.status_code == 200:
    print("✅ AES key securely exchanged!")
else:
    # Print the response text for debugging
    print("Response Text:", response.text)
    print(f"❌ Failed to exchange AES key: {response.json()}")


# WebSocket Client Setup
sio = socketio.Client()

def send_message(message):
    if not aes_key:
        print("❌ AES key missing! Unable to send messages.")
        return

    encrypted_message = aes_encrypt(message, aes_key)
    sio.emit("message", {"data": base64.b64encode(encrypted_message).decode('utf-8')})

@sio.on("message")
def handle_message(data):
    encrypted_message = base64.b64decode(data.get("message"))

    try:
        decrypted_message = aes_decrypt(encrypted_message, aes_key).decode()
        print(f"🔒 Received Message: {decrypted_message}")
    except Exception as e:
        print(f"❌ Decryption Failed: {str(e)}")

if __name__ == "__main__":
    try:
        sio.connect(SERVER_URL)
        print("✅ Connected to SecureChat Server")

        while True:
            message = input("Enter message: ")
            send_message(message)
    except Exception as e:
        print(f"❌ Connection Error: {e}")

