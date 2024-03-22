import sqlite3
import os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding

DATABASE_FILE = "users.db"
DATABASE_SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    user TEXT UNIQUE,
    password BLOB,
    directory TEXT
);
"""

def initialize_database():
    if os.path.exists(DATABASE_FILE):
        # Check if existing database has correct schema
        conn = sqlite3.connect(DATABASE_FILE)
        cursor = conn.cursor()
        cursor.execute("PRAGMA table_info(users)")
        columns = cursor.fetchall()
        if len(columns) != 3 or columns[0][1] != "user" or columns[1][1] != "password" or columns[2][1] != "directory":
            # Rename existing file and create new database
            os.rename(DATABASE_FILE, DATABASE_FILE + ".bak")
            print("Old users database file renamed to users.db.bak")
            create_database()
        else:
            conn.close()
    else:
        create_database()

def create_database():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute(DATABASE_SCHEMA)
    conn.commit()
    conn.close()

def list_users():
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT user, directory FROM users")
    users = cursor.fetchall()
    conn.close()
    print("Users:")
    for user in users:
        print(f"Username: {user[0]}, Root Directory: {user[1]}")

def add_user():
    username = input("Enter username: ")
    password = input("Enter password: ")
    directory = input("Enter root directory: ")
    
    # Encrypt password
    encrypted_password = encrypt_password(password)

    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO users (user, password, directory) VALUES (?, ?, ?)", (username, encrypted_password, directory))
    conn.commit()
    conn.close()
    print("User added successfully.")

def modify_user():
    username = input("Enter username to modify: ")
    new_username = input("Enter new username (press Enter to skip): ")
    new_password = input("Enter new password (press Enter to skip): ")
    new_directory = input("Enter new root directory (press Enter to skip): ")
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    if new_username:
        cursor.execute("UPDATE users SET user=? WHERE user=?", (new_username, username))
    if new_password:
        # Encrypt new password
        encrypted_password = encrypt_password(new_password)
        cursor.execute("UPDATE users SET password=? WHERE user=?", (encrypted_password, username))
    if new_directory:
        cursor.execute("UPDATE users SET directory=? WHERE user=?", (new_directory, username))
    conn.commit()
    conn.close()
    print("User modified successfully.")


def remove_user():
    username = input("Enter username to remove: ")
    conn = sqlite3.connect(DATABASE_FILE)
    cursor = conn.cursor()
    cursor.execute("DELETE FROM users WHERE user=?", (username,))
    conn.commit()
    conn.close()
    print("User removed successfully.")

def generate_key_pair():
    private_key = serialization.load_pem_private_key(
        # Replace 'private_key.pem' with your private key file path
        open('private_key.pem', 'rb').read(),
        password=None,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return public_key

def encrypt_password(password):
    # Generate public key
    public_key = generate_key_pair()
    # Encrypt password
    encrypted_password = public_key.encrypt(
        password.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted_password

def main():
    initialize_database()
    while True:
        print("\n1. List users")
        print("2. Add user")
        print("3. Modify user")
        print("4. Remove user")
        print("5. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            list_users()
        elif choice == "2":
            add_user()
        elif choice == "3":
            modify_user()
        elif choice == "4":
            remove_user()
        elif choice == "5":
            break
        else:
            print("Invalid choice. Please choose again.")

if __name__ == "__main__":
    main()
