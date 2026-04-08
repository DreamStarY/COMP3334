from flask import Flask, request, jsonify, session
import bcrypt
import sqlite3
from flask_cors import CORS
import random
import time
from friend_manager import FriendManager
from crypto_manager import CryptoManager
from flask_session import Session
import base64
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
CORS(app)

# Configure session management
app.config['SESSION_TYPE'] = 'filesystem'
Session(app)

current_random_otp = "------"
friend_mgr = FriendManager('im_system.db', 'users.db')
online_users = set()

# Retention policy
QUEUE_TTL_SECONDS = 7 * 24 * 60 * 60  # queued ciphertext self-destruct after 7 days
MESSAGE_RETENTION_SECONDS = 30 * 24 * 60 * 60  # delivered messages retained for 30 days

def init_db():
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (username TEXT PRIMARY KEY, hashed_pw TEXT, public_key TEXT)''')
    conn.commit()
    conn.close()
    
    # Initialize friendship table
    friend_mgr.create_friendship_table()
    
    # Initialize messages table
    msgs_conn = sqlite3.connect('messages.db')
    msgs_c = msgs_conn.cursor()
    msgs_c.execute('''CREATE TABLE IF NOT EXISTS messages
                    (msg_id TEXT PRIMARY KEY,
                     sender TEXT NOT NULL,
                     recipient TEXT NOT NULL,
                     ciphertext BLOB NOT NULL,
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                     delivery_status TEXT DEFAULT 'SENT',
                     is_read INTEGER DEFAULT 0,
                     FOREIGN KEY(sender) REFERENCES users(username),
                     FOREIGN KEY(recipient) REFERENCES users(username))''')
    msgs_conn.commit()
    msgs_conn.close()

# R21 Retention and cleanup 

def cleanup_queued_messages():
    cutoff = int(time.time() - QUEUE_TTL_SECONDS)
    msgs_conn = sqlite3.connect('messages.db')
    msgs_c = msgs_conn.cursor()
    msgs_c.execute('''DELETE FROM queued_messages
                     WHERE strftime('%s', queued_at) < ?''', (cutoff,))
    deleted = msgs_c.rowcount
    msgs_conn.commit()
    msgs_conn.close()
    return deleted


def cleanup_old_messages():
    cutoff = int(time.time() - MESSAGE_RETENTION_SECONDS)
    msgs_conn = sqlite3.connect('messages.db')
    msgs_c = msgs_conn.cursor()
    msgs_c.execute('''DELETE FROM messages
                     WHERE strftime('%s', timestamp) < ?''', (cutoff,))
    deleted = msgs_c.rowcount
    msgs_conn.commit()
    msgs_conn.close()
    return deleted

    # R20 offline message delivery queue
def deliver_queued_messages(recipient):
    msgs_conn = sqlite3.connect('messages.db')
    msgs_c = msgs_conn.cursor()
    msgs_c.execute('''SELECT msg_id, sender, ciphertext, timestamp FROM queued_messages
                     WHERE recipient = ? ORDER BY queued_at ASC''', (recipient,))
    queued = msgs_c.fetchall()
    delivered_count = 0
    for msg_id, sender, ciphertext, timestamp in queued:
        msgs_c.execute('''INSERT OR IGNORE INTO messages
                         (msg_id, sender, recipient, ciphertext, timestamp, delivery_status, is_read)
                         VALUES (?, ?, ?, ?, ?, ?, 0)''',
                      (msg_id, sender, recipient, ciphertext, timestamp, 'DELIVERED'))
        delivered_count += 1
    msgs_c.execute('DELETE FROM queued_messages WHERE recipient = ?', (recipient,))
    msgs_conn.commit()
    msgs_conn.close()
    return delivered_count


def generate_random_otp():
    global current_random_otp
    current_random_otp = f"{random.randint(0, 999999):06d}"

@app.route("/register", methods=["POST"])
def register():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "msg": "Username and password cannot be empty"}), 400

    # Generate X25519 key pair
    private_key, public_key = CryptoManager.generate_key_pair()
    private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("INSERT INTO users (username, hashed_pw, public_key) VALUES (?, ?, ?)",
                  (username, password, public_key_bytes.decode('utf-8')))
        conn.commit()
        return jsonify({"status": "ok", "msg": "Registration successful"})
    except sqlite3.IntegrityError:
        return jsonify({"status": "error", "msg": "Username already exists"}), 400
    finally:
        conn.close()

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")

    if not username or not password:
        return jsonify({"status": "error", "msg": "Username and password cannot be empty"}), 400

    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    try:
        c.execute("SELECT hashed_pw, public_key FROM users WHERE username = ?", (username,))
        result = c.fetchone()
        if result and result[0] == password:
            session['username'] = username
            return jsonify({"status": "ok", "msg": "Login successful", "public_key": result[1]})
        else:
            return jsonify({"status": "error", "msg": "Invalid username or password"}), 401
    finally:
        conn.close()

@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"status": "ok", "msg": "Logged out successfully"})

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

# ==================== Friend Management Endpoints ====================

@app.route("/send-friend-request", methods=["POST"])
def send_friend_request():
    data = request.json
    sender_id = data.get("sender_id")
    target_info = data.get("target_info")
    result = friend_mgr.send_friend_request(sender_id, target_info)
    return jsonify(result)

@app.route("/get-pending-requests", methods=["POST"])
def get_pending_requests():
    my_identifier = request.json.get("my_identifier")
    pending = friend_mgr.get_pending_requests(my_identifier)
    return jsonify(pending)

@app.route("/respond-to-request", methods=["POST"])
def respond_to_request():
    data = request.json
    my_identifier = data.get("my_identifier")
    sender_identifier = data.get("sender_identifier")
    action = data.get("action")  # 'ACCEPTED' or 'DECLINED'
    success = friend_mgr.respond_to_request(my_identifier, sender_identifier, action)
    return jsonify({"status": "ok" if success else "error", "success": success})

@app.route("/cancel-request", methods=["POST"])
def cancel_request():
    data = request.json
    my_identifier = data.get("my_identifier")
    target_identifier = data.get("target_identifier")
    success = friend_mgr.cancel_request(my_identifier, target_identifier)
    return jsonify({"status": "ok" if success else "error", "success": success})

@app.route("/remove-friend", methods=["POST"])
def remove_friend():
    data = request.json
    my_identifier = data.get("my_identifier")
    target_identifier = data.get("target_identifier")
    success = friend_mgr.remove_friend(my_identifier, target_identifier)
    return jsonify({"status": "ok" if success else "error", "success": success})

@app.route("/block-user", methods=["POST"])
def block_user():
    data = request.json
    my_identifier = data.get("my_identifier")
    target_identifier = data.get("target_identifier")
    success = friend_mgr.block_user(my_identifier, target_identifier)
    return jsonify({"status": "ok" if success else "error", "success": success})

@app.route("/check-friendship", methods=["POST"])
def check_friendship():
    data = request.json
    sender_ident = data.get("sender_ident")
    receiver_ident = data.get("receiver_ident")
    is_friend = friend_mgr.check_friends(sender_ident, receiver_ident)
    return jsonify({"is_friend": is_friend})

@app.route("/get-accepted-friends", methods=["POST"])
def get_accepted_friends():
    user = request.json.get("user")
    
    try:
        # Query friendships table for accepted friends
        friends_conn = sqlite3.connect('im_system.db')
        friends_c = friends_conn.cursor()
        
        friends_c.execute('''
            SELECT 
                CASE WHEN user_identifier = ? THEN friend_identifier ELSE user_identifier END as friend
            FROM friendships 
            WHERE (user_identifier = ? OR friend_identifier = ?) 
            AND status = 'ACCEPTED'
        ''', (user, user, user))
        
        rows = friends_c.fetchall()
        friends_conn.close()
        
        friends = [row[0] for row in rows]
        return jsonify({"status": "ok", "friends": friends})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

def run_server():
    init_db()
    generate_random_otp()
    app.run(host="127.0.0.1", port=5000, use_reloader=False)