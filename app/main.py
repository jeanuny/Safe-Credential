from cryptography.fernet import Fernet
import base64
import hashlib
import bcrypt
import json
import os

DATA_FILE = 'app/data.json'
OTP_FILE = 'app/otps.json'

def get_key(master_password: str) -> bytes:
    # Derive a 32-byte Fernet key from the master password
    key = hashlib.sha256(master_password.encode()).digest()
    return base64.urlsafe_b64encode(key)

def encrypt(data: str, key: bytes) -> bytes:
    f = Fernet(key)
    return f.encrypt(data.encode())

def decrypt(data: bytes, key: bytes) -> str:
    f = Fernet(key)
    return f.decrypt(data).decode()

def hash_master_password(master_password: str) -> bytes:
    return bcrypt.hashpw(master_password.encode(), bcrypt.gensalt())

def verify_master_password(password: str, hashed: bytes) -> bool:
    return bcrypt.checkpw(password.encode(), hashed)

def load_data() -> dict:
    if not os.path.exists(DATA_FILE):
        return {}
    with open(DATA_FILE, 'r') as f:
        return json.load(f)

def load_otps() -> dict:
    if not os.path.exists(OTP_FILE):
        return {}
    with open(OTP_FILE, 'r') as f:
        return json.load(f)

def save_data(data: dict):
    with open(DATA_FILE, 'w') as f:
        json.dump(data, f, indent=4)

def delete_entry(data: dict, website: str) -> None:
    if website in data:
        del data[website]
        save_data(data)
        print(f"Entry for {website} deleted.")
    else:
        print(f"No entry found for {website}.")

def new_entry(data: dict, key: bytes) -> None:
    website = input("Enter Website name: ")
    username = input("Enter username: ")
    password = input("Enter password: ")
    encrypted_password = encrypt(password, key).decode()
    data[website] = {
        'username': username,
        'password': encrypted_password
    }
    save_data(data)
    print(f"Entry for {website} added.")

def view_entries(data: dict, key: bytes) -> None:
    for website, entry in data.items():
        decrypted_password = decrypt(entry['password'].encode(), key)
        print(f"Website: {website}, Username: {entry['username']}, Password: {decrypted_password}")

# def main():
#     data = load_data()
#     master_password = input("Enter master password: ")
#     key = get_key(master_password)

#     while True:
#         print("1. Add new entry\n2. View entries\n3. Exit")
#         choice = input("Choose an option: ")
#         if choice == '1':
#             new_entry(data, key)
#         elif choice == '2':
#             view_entries(data, key)
#         elif choice == '3':
#             break

# if __name__ == "__main__":
#     main()
