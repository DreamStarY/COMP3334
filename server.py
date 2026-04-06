from flask import Flask, request, jsonify
import bcrypt
import sqlite3
from flask_cors import CORS
import random
import time
from friend_manager import FriendManager

app = Flask(__name__)
CORS(app)

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
    
    # Initialize queued messages table for offline delivery
    msgs_c.execute('''CREATE TABLE IF NOT EXISTS queued_messages
                    (queue_id INTEGER PRIMARY KEY AUTOINCREMENT,
                     msg_id TEXT UNIQUE,
                     sender TEXT NOT NULL,
                     recipient TEXT NOT NULL,
                     ciphertext BLOB NOT NULL,
                     timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                     queued_at DATETIME DEFAULT CURRENT_TIMESTAMP)''')
    
    # Add is_read column if it doesn't exist (for existing databases)
    try:
        msgs_c.execute("ALTER TABLE messages ADD COLUMN is_read INTEGER DEFAULT 0")
    except sqlite3.OperationalError:
        # Column already exists
        pass
    
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

    cleanup_old_messages()
    queued_delivered = deliver_queued_messages(username)
    online_users.add(username)
    return jsonify({"status":"ok","msg":"登录成功","public_key":user[1],"queued_delivered": queued_delivered})

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

@app.route("/logout", methods=["POST"])
def logout():
    data = request.json
    username = data.get("username")
    online_users.discard(username)
    return jsonify({"status": "ok", "msg": "已退出登录"})

# ==================== Message Endpoints ====================

@app.route("/send-message", methods=["POST"])
def send_message():
    data = request.json
    sender = data.get("sender")
    recipient = data.get("recipient")
    ciphertext = data.get("ciphertext")  # base64-encoded or hex string
    msg_id = data.get("msg_id")
    created_at = data.get("created_at")
    
    # Verify sender and recipient are friends
    if not friend_mgr.check_friends(sender, recipient):
        return jsonify({"status": "error", "message": "Not friends or blocked"})
    
    try:
        current_ts = int(time.time())
        if not msg_id:
            msg_id = f"msg_{int(current_ts * 1000)}"
        try:
            created_ts = int(created_at) if created_at is not None else current_ts
        except Exception:
            created_ts = current_ts
        
        if created_ts < current_ts - QUEUE_TTL_SECONDS:
            return jsonify({"status": "error", "message": "Message expired or replay rejected"})
        
        cleanup_queued_messages()
        cleanup_old_messages()
        msgs_conn = sqlite3.connect('messages.db')
        msgs_c = msgs_conn.cursor()
        msgs_c.execute("SELECT 1 FROM messages WHERE msg_id = ?", (msg_id,))
        if msgs_c.fetchone():
            msgs_conn.close()
            return jsonify({"status": "ok", "msg_id": msg_id, "queued": False, "duplicate": True})
        msgs_c.execute("SELECT 1 FROM queued_messages WHERE msg_id = ?", (msg_id,))
        if msgs_c.fetchone():
            msgs_conn.close()
            return jsonify({"status": "ok", "msg_id": msg_id, "queued": True, "duplicate": True})
        
        if recipient in online_users:
            msgs_c.execute('''INSERT INTO messages (msg_id, sender, recipient, ciphertext, timestamp, delivery_status) 
                             VALUES (?, ?, ?, ?, ?, ?)''',
                          (msg_id, sender, recipient, ciphertext, created_ts, 'SENT'))
            queued = False
        else:
            msgs_c.execute('''INSERT INTO queued_messages (msg_id, sender, recipient, ciphertext, timestamp) 
                             VALUES (?, ?, ?, ?, ?)''',
                          (msg_id, sender, recipient, ciphertext, created_ts))
            queued = True
        msgs_conn.commit()
        msgs_conn.close()
        return jsonify({"status": "ok", "msg_id": msg_id, "queued": queued})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/get-messages", methods=["POST"])
def get_messages():
    data = request.json
    user = data.get("user")
    contact = data.get("contact")
    limit = data.get("limit", 20)  # Reduced default limit
    before_message_id = data.get("before_message_id")  # New parameter for pagination
    
    try:
        msgs_conn = sqlite3.connect('messages.db')
        msgs_c = msgs_conn.cursor()
        
        # Build query with optional pagination
        query = '''SELECT msg_id, sender, recipient, ciphertext, timestamp, delivery_status
                   FROM messages
                   WHERE (sender = ? AND recipient = ?) OR (sender = ? AND recipient = ?)'''
        params = [user, contact, contact, user]
        
        if before_message_id:
            # Get timestamp of the before_message_id to paginate
            msgs_c.execute('''SELECT timestamp FROM messages WHERE msg_id = ?''', (before_message_id,))
            before_row = msgs_c.fetchone()
            if before_row:
                query += " AND timestamp < ?"
                params.append(before_row[0])
        
        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)
        
        msgs_c.execute(query, params)
        rows = msgs_c.fetchall()
        msgs_conn.close()
        
        messages = [
            {
                "msg_id": row[0],
                "sender": row[1],
                "recipient": row[2],
                "ciphertext": row[3],
                "timestamp": row[4],
                "delivery_status": row[5]
            }
            for row in rows
        ]
        
        # Check if there are more messages available
        has_more = len(messages) == limit
        
        return jsonify({
            "status": "ok", 
            "messages": messages,
            "has_more": has_more,
            "limit": limit
        })
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    
    #   R23 conversation list 

@app.route("/get-conversation-list", methods=["POST"])
def get_conversation_list():
    user = request.json.get("user")
    
    try:
        msgs_conn = sqlite3.connect('messages.db')
        msgs_c = msgs_conn.cursor()
        
        # Get latest message for each contact (ordered by most recent), including queued offline messages
        msgs_c.execute('''
            WITH all_msgs AS (
                SELECT msg_id, sender, recipient, ciphertext, timestamp, is_read FROM messages
                UNION ALL
                SELECT msg_id, sender, recipient, ciphertext, timestamp, 0 AS is_read FROM queued_messages
            ),
            conversation_partners AS (
                SELECT 
                    CASE WHEN sender = ? THEN recipient ELSE sender END AS contact,
                    MAX(timestamp) AS last_time,
                    SUM(CASE WHEN sender != ? AND is_read = 0 THEN 1 ELSE 0 END) AS unread_count
                FROM all_msgs
                WHERE sender = ? OR recipient = ?
                GROUP BY contact
            )
            SELECT 
                cp.contact,
                cp.last_time,
                am.ciphertext AS last_message,
                cp.unread_count
            FROM conversation_partners cp
            JOIN all_msgs am ON (
                (am.sender = ? AND am.recipient = cp.contact) OR 
                (am.sender = cp.contact AND am.recipient = ?)
            ) AND am.timestamp = cp.last_time
            ORDER BY cp.last_time DESC
        ''', (user, user, user, user, user, user))
        
        rows = msgs_c.fetchall()
        msgs_conn.close()
        
        conversations = [
            {
                "contact": row[0],
                "last_time": row[1],
                "last_message": row[2],
                "unread_count": row[3]
            }
            for row in rows
        ]
        return jsonify({"status": "ok", "conversations": conversations})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})
    
    # R24 mark messages as read

@app.route("/mark-messages-read", methods=["POST"])
def mark_messages_read():
    data = request.json
    user = data.get("user")
    contact = data.get("contact")
    
    try:
        msgs_conn = sqlite3.connect('messages.db')
        msgs_c = msgs_conn.cursor()
        
        # Mark all messages from contact to user as read
        msgs_c.execute('''
            UPDATE messages 
            SET is_read = 1 
            WHERE sender = ? AND recipient = ? AND is_read = 0
        ''', (contact, user))
        
        msgs_conn.commit()
        msgs_conn.close()
        return jsonify({"status": "ok"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

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