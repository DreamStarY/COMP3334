from flask import Flask, request, jsonify
import bcrypt
import sqlite3
from flask_cors import CORS
import random
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
CORS(app)

current_random_otp = "------"

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY,
                  hashed_pw TEXT,
                  private_key TEXT,
                  public_key TEXT)''')
    conn.commit()
    conn.close()

def generate_random_otp():
    global current_random_otp
    current_random_otp = f"{random.randint(0, 999999):06d}"
    return current_random_otp

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()

    pri_key = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    pub_key = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return pri_key, pub_key

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()

    # ======================
    # 强制密码 >8 位
    # ======================
    if len(password) <= 8:
        return jsonify({
            "status": "error",
            "msg": "密码长度必须大于8位，请重新输入"
        })

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username=?", (username,))
    if c.fetchone():
        conn.close()
        return jsonify({"status": "error", "msg": "用户名已存在"})

    hashed_pw = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    private_key, public_key = generate_key_pair()

    c.execute("INSERT INTO users VALUES (?, ?, ?, ?)",
              (username, hashed_pw, private_key, public_key))
    conn.commit()
    conn.close()

    return jsonify({"status": "ok", "msg": "注册成功"})

@app.route("/login", methods=["POST"])
def login():
    u = request.json.get("username")
    p = request.json.get("password")
    input_otp = request.json.get("otp")

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute("SELECT hashed_pw FROM users WHERE username=?", (u,))
    user = c.fetchone()
    conn.close()

    if not user:
        return jsonify({"status": "error", "msg": "用户不存在"})
    if not bcrypt.checkpw(p.encode(), user[0].encode()):
        return jsonify({"status": "error", "msg": "密码错误"})
    if input_otp != current_random_otp:
        return jsonify({"status": "error", "msg": "OTP错误"})

    return jsonify({"status": "ok", "msg": "登录成功"})

@app.route("/get-otp", methods=["POST"])
def get_otp():
    return jsonify({"otp": current_random_otp})

def run_server():
    init_db()
    generate_random_otp()
    app.run(port=5000, use_reloader=False)