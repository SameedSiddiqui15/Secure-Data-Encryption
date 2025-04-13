# Importing libraries
import streamlit as st 
import hashlib
import json
import os 
import time
from cryptography.fernet import Fernet
from base64 import urlsafe_b64encode
from hashlib import pbkdf2_hmac


DATA_FILE = "secure_data.json"
SALT = b"secure_salt_value"  # Used for password hashing
LOCKOUT_DURATION = 60  # Lockout time in seconds after 3 failed login attempts

# Initializing session state variables
if "authenticated_user" not in st.session_state:
    st.session_state.authenticated_user = None
if "failed_attempts" not in st.session_state:
    st.session_state.failed_attempts = 0
if "lockout_time" not in st.session_state:
    st.session_state.lockout_time = 0

# Load data from JSON file
def load_data():
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            return json.load(f)
    return {}

# Save data to JSON file
def save_data(data):
    with open(DATA_FILE, "w") as f:
        json.dump(data, f)
    return {}

# Generate encryption key using PBKDF2
def generate_key(passkey):
    key = pbkdf2_hmac('sha256', passkey.encode(), SALT, 100000)
    return urlsafe_b64encode(key)

# Hash the password securely
def hash_password(password):
    return hashlib.pbkdf2_hmac('sha256', password.encode(), SALT, 100000).hex()

# Encrypt text using Fernet
def encrypt_text(text, key):
    cipher = Fernet(generate_key(key))  # Create cipher using derived key
    return cipher.encrypt(text.encode()).decode()

# Decrypt text using Fernet
def decrypt_text(encrypt_text, key):
    try:
        cipher = Fernet(generate_key(key))
        return cipher.decrypt(encrypt_text.encode()).decode()
    except:
        return None

# Load existing user data
stored_data = load_data()

st.title("Secure Multi-User Data System 🔐")
menu = ["Home", "Register", "Login", "Store Data", "Retrieve Data"]
if "choice" not in st.session_state:
    st.session_state["choice"] = "Home"

selected_index = menu.index(st.session_state["choice"])
st.session_state["choice"] = st.sidebar.selectbox("Navigation", menu, index=selected_index)
choice = st.session_state.choice

# === Home Page ===
if choice == "Home":
    st.subheader("Welcome To My Data Encryption System Using streamlit 🏠!")
    st.markdown("Securely store & retrieve your data with encryption. Each user has their own protected data.")

# === Register Page ===
elif choice == "Register":
    st.subheader("📝 Register New User")
    username = st.text_input("Choose Username")
    password = st.text_input("Choose Password", type="password")

    if st.button("Register"):
        if username and password:
            if username in stored_data:
                st.warning("⚠️ User already exists. Login please...")
            else:
                # Store new user with hashed password and empty data list
                stored_data[username] = {
                    "password": hash_password(password),
                    "data": []
                }
                save_data(stored_data)
                st.success("You Registered Successfully!✅")
                time.sleep(1)
                st.session_state.choice = "Login"
                st.experimental_rerun()
        else:
            st.error("❌ Both fields are required & must be filled correctly.")

# === Login Page ===
elif choice == "Login":
    st.subheader("🔑 User Login")
    
    # Lockout check
    if time.time() < st.session_state.lockout_time:
        remaining = int(st.session_state.lockout_time - time.time())
        st.error(f"⏳ Too many failed attempts. Please wait {remaining} seconds.")
        st.stop()

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        # Validate login credentials
        if username in stored_data and stored_data[username]["password"] == hash_password(password):
            st.session_state.authenticated_user = username
            st.session_state.failed_attempts = 0
            st.success(f"✅ Welcome {username}!")
            # time.sleep(1)
            st.session_state.choice = "Store Data"
            st.experimental_rerun
        else:
            st.session_state.failed_attempts += 1
            remaining = 3 - st.session_state.failed_attempts
            st.warning(f"⚠️ Invalid credentials! Attempts left: {remaining}")

            # Lockout after 3 failed attempts
            if st.session_state.failed_attempts >= 3:
                st.session_state.lockout_time = time.time() + LOCKOUT_DURATION
                st.error("🚫 Too many failed attempts. Locked for 60 seconds.")
                st.stop()

# === Store Encrypted Data Page ===
elif choice == "Store Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please login first.")
    else:
        st.subheader("📦 Store Encrypted Data")
        data = st.text_area("Enter data to encrypt")
        passkey = st.text_input("Encryption Key (passphrase)", type="password")

        if st.button("Encrypt & Save"):
            if data and passkey:
                encrypted = encrypt_text(data, passkey)
                # Save encrypted data to the user's list
                stored_data[st.session_state.authenticated_user]["data"].append(encrypted)
                save_data(stored_data)
                st.success("✅ Data encrypted and saved!")
                time.sleep(1)
                st.session_state.choice = "Retrieve Data"
                st.experimental_rerun()
            else:
                st.error("All fields are required.")

# === Retrieve Data Page ===
elif choice == "Retrieve Data":
    if not st.session_state.authenticated_user:
        st.warning("🔓 Please login first.")
    else:
        st.subheader("🔎 Retrieve Data")
        user_data = stored_data.get(st.session_state.authenticated_user, {}).get("data", [])

        if not user_data:
            st.info("ℹ️ No data found.")
        else:
            st.write("🔐 Encrypted Data Entries:")
            for i, item in enumerate(user_data):
                st.code(item, language="text")
                
            encrypted_input = st.text_area("Enter Encrypted Text")
            passkey = st.text_input("Enter Passkey to Decrypt", type="password")

            if st.button("Decrypt"):
                result = decrypt_text(encrypted_input, passkey)
                if result:
                    st.success(f"✅ Decrypted: {result}")
                else:
                    st.error("❌ Incorrect passkey or corrupted data.")
