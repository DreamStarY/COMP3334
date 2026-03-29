from flask import Flask, request, jsonify
import bcrypt
import sqlite3
from flask_cors import CORS
import random

app = Flask(__name__)
CORS(app)

current_random_otp = "------"

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, hashed_pw TEXT, public_key TEXT)''')
    conn.commit()
    conn.close()

def generate_random_otp():
    global current_random_otp
    current_random_otp = f"{random.randint(0, 999999):06d}"

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    public_key = data.get("public_key", "").strip()

    if len(password) <= 8:
        return jsonify({"status":"error","msg":"密码必须大于8位"})

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"status":"error","msg":"用户名已存在"})

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    c.execute("INSERT INTO users VALUES (?,?,?)", (username, hashed_pw, public_key))
    conn.commit()
    conn.close()
    return jsonify({"status":"ok","msg":"注册成功"})

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    otp_input = data.get("otp")

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT hashed_pw, public_key FROM users WHERE username=?", (username,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"status":"error","msg":"用户不存在"})
    if not bcrypt.checkpw(password.encode(), user[0].encode()):
        return jsonify({"status":"error","msg":"密码错误"})
    if otp_input != current_random_otp:
        return jsonify({"status":"error","msg":"OTP错误"})

    return jsonify({"status":"ok","msg":"登录成功","public_key":user[1]})

@app.route("/get-public-key", methods=["POST"])
def get_public_key():
    username = request.json.get("username")
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT public_key FROM users WHERE username=?", (username,))
    res = c.fetchone()
    conn.close()
    return jsonify({"public_key": res[0] if res else ""})

@app.route("/get-otp", methods=["POST"])
def get_otp():
    return jsonify({"otp": current_random_otp})

def run_server():
    init_db()
    generate_random_otp()
    app.run(host="127.0.0.1", port=5000, use_reloader=False)