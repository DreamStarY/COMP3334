import sqlite3

class FriendManager:
    def __init__(self, db_path='im_system.db', users_db_path='users.db'):
        """
        初始化 FriendManager 并设置数据库路径。
        在实际的系统中，这里的 db_path 应该通过配置文件或全局变量传入。
        """
        self.db_path = db_path
        self.users_db_path = users_db_path

    # ==========================================
    # [R13, R14, R15] 创建底层好友关系表
    # ==========================================
    def create_friendship_table(self):
        """
        R13, R14, R15: 使用文本标识符创建好友关系表
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # 创建好友关系表，直接存储标识符（用户名/邮箱/联系码）
        # status 涵盖了 PENDING (R13), ACCEPTED/DECLINED (R14), BLOCKED (R15)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS friendships (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_identifier TEXT NOT NULL,      -- 发起者的标识符
                friend_identifier TEXT NOT NULL,    -- 接收者的标识符
                status TEXT NOT NULL CHECK(
                    status IN ('PENDING', 'ACCEPTED', 'DECLINED', 'BLOCKED')
                ),
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
                -- 确保同一对标识符之间不会重复发起请求
                UNIQUE(user_identifier, friend_identifier)
            )
        ''')

        conn.commit()
        conn.close()
        print(" Friends relationship table is created.")

    # ==========================================
    # [R13] 发送好友请求
    # ==========================================
    def send_friend_request(self, sender_id, target_info):
        """
        实现 R13: 严格通过 username (包含 email 格式) 或 contact code 发送请求 
        :param sender_id: 发送者 ID
        :param target_info: 用户输入的字符串（可能是用户名、邮箱或在线临时联系码）
        """
        # Query users from users.db to find target
        users_conn = sqlite3.connect(self.users_db_path)
        users_cursor = users_conn.cursor()
        
        try:
            # 1. 查 username
            users_cursor.execute('''
                SELECT username FROM users 
                WHERE username = ?
            ''', (target_info,))
            
            target = users_cursor.fetchone()
            users_conn.close()
            
            if not target:
                return {"status": "error", "message": "No matching user found (please check that your username, email address, or contact code is valid)"}
            
            target_id = target[0]
            
            # Now work with friendships table in im_system.db
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            # 2. 不能加自己
            if sender_id == target_id:
                return {"status": "error", "message": "can't add yourself as a friend"}

            # 3. 必须经过请求流程，不能直接添加
            cursor.execute('''
                SELECT status FROM friendships 
                WHERE (user_identifier = ? AND friend_identifier = ?) 
                   OR (user_identifier = ? AND friend_identifier = ?)
            ''', (sender_id, target_id, target_id, sender_id))
            
            existing = cursor.fetchone()
            if existing:
                status = existing[0]
                if status == 'ACCEPTED': return {"status": "error", "message": "already friends"}
                if status == 'PENDING': return {"status": "error", "message": "Your request is being processed"}
                if status == 'BLOCKED': return {"status": "error", "message": "Unable to send the request(block)"}

            # 4. 默认非即时添加
            cursor.execute('''
                INSERT INTO friendships (user_identifier, friend_identifier, status) 
                VALUES (?, ?, 'PENDING')
            ''', (sender_id, target_id))

            conn.commit()
            return {"status": "success", "message": "Friend request sent"}

        except sqlite3.Error as e:
            return {"status": "error", "message": f"Database error: {e}"}
        finally:
            conn.close()

    # ==========================================
    # [R14] 查看待处理的好友请求
    # ==========================================
    def get_pending_requests(self, my_identifier):
        """
        R14: 双方查看待处理请求 
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 别人发给我的 (我是接收方)
        cursor.execute('''
            SELECT user_identifier FROM friendships 
            WHERE friend_identifier = ? AND status = 'PENDING'
        ''', (my_identifier,))
        incoming = [row[0] for row in cursor.fetchall()]
        
        # 我发给别人的 (我是发送方)
        cursor.execute('''
            SELECT friend_identifier FROM friendships 
            WHERE user_identifier = ? AND status = 'PENDING'
        ''', (my_identifier,))
        outgoing = [row[0] for row in cursor.fetchall()]
        
        conn.close()
        return {"incoming": incoming, "outgoing": outgoing}

    # ==========================================
    # [R14] 处理收到的好友请求 (接受/拒绝)
    # ==========================================
    def respond_to_request(self, my_identifier, sender_identifier, action):
        """
        R14: 接收方处理请求 (Accept/Decline) 
        action 只能是 'ACCEPTED' 或 'DECLINED'
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 严格权限检查：WHERE 子句确保只有 friend_identifier (接收方) 能更新状态
        cursor.execute('''
            UPDATE friendships 
            SET status = ?
            WHERE user_identifier = ? AND friend_identifier = ? AND status = 'PENDING'
        ''', (action, sender_identifier, my_identifier))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    # ==========================================
    # [R14] 取消已发送的好友请求
    # ==========================================
    def cancel_request(self, my_identifier, target_identifier):
        """
        R14: 发送方取消请求 
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 严格权限检查：WHERE 子句确保只有 user_identifier (发送方) 能执行删除
        # 且只能删除状态为 PENDING 的记录
        cursor.execute('''
            DELETE FROM friendships 
            WHERE user_identifier = ? AND friend_identifier = ? AND status = 'PENDING'
        ''', (my_identifier, target_identifier))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    # ==========================================
    # [R15] 移除现有好友
    # ==========================================
    def remove_friend(self, my_identifier, target_identifier):
        """
        R15: 移除好友。直接删除已存在的 ACCEPTED 记录。
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 无论谁发起的申请，只要状态是 ACCEPTED，就删除这条关系
        cursor.execute('''
            DELETE FROM friendships 
            WHERE status = 'ACCEPTED' AND (
                (user_identifier = ? AND friend_identifier = ?) OR 
                (user_identifier = ? AND friend_identifier = ?)
            )
        ''', (my_identifier, target_identifier, target_identifier, my_identifier))
        
        success = cursor.rowcount > 0
        conn.commit()
        conn.close()
        return success

    # ==========================================
    # [R15] 拉黑用户
    # ==========================================
    def block_user(self, my_identifier, target_identifier):
        """
        R15: 拉黑用户。
        哪怕之前不是好友，也要创建一个 BLOCKED 记录来拦截后续操作。
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. 检查是否已经存在任何关系记录（PENDING, ACCEPTED, DECLINED）
        cursor.execute('''
            SELECT id FROM friendships 
            WHERE (user_identifier = ? AND friend_identifier = ?) OR 
                  (user_identifier = ? AND friend_identifier = ?)
        ''', (my_identifier, target_identifier, target_identifier, my_identifier))
        
        existing = cursor.fetchone()
        
        if existing:
            # 如果存在记录，将其更新为 BLOCKED
            # user_identifier 是主动拉黑者，friend_identifier 是被拉黑者, 需要区分主次来区别哪边信息被blocked
            cursor.execute('''
                UPDATE friendships 
                SET user_identifier = ?, friend_identifier = ?, status = 'BLOCKED', updated_at = CURRENT_TIMESTAMP
                WHERE id = ?
            ''', (my_identifier, target_identifier, existing[0]))
        else:
            # 如果之前没关系，直接插入一条新的 BLOCKED 记录
            cursor.execute('''
                INSERT INTO friendships (user_identifier, friend_identifier, status) 
                VALUES (?, ?, 'BLOCKED')
            ''', (my_identifier, target_identifier))
            
        conn.commit()
        conn.close()
        return True

    # ==========================================
    # [R16] 默认防垃圾消息检查 (核心安全拦截)
    # ==========================================
    def check_friends(self, sender_ident, receiver_ident):
        """
        R16: 核心安全检查逻辑。
        检查 sender 和 receiver 是否拥有 'ACCEPTED' 状态的好友关系。
        同时确保接收方没有拉黑发送方。
        """
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # 1. 检查是否存在双向认可的好友关系 (R14: ACCEPTED)
        # 无论当初是谁发起的申请，只要状态是 ACCEPTED，就是好友
        cursor.execute('''
            SELECT status FROM friendships 
            WHERE status = 'ACCEPTED' AND (
                (user_identifier = ? AND friend_identifier = ?) OR 
                (user_identifier = ? AND friend_identifier = ?)
            )
        ''', (sender_ident, receiver_ident, receiver_ident, sender_ident))
        
        friendship = cursor.fetchone()
        
        # 2. 检查黑名单状态 (R15: BLOCKED) 
        # 特别检查接收方 (receiver) 是否把发送方 (sender) 拉黑了
        cursor.execute('''
            SELECT id FROM friendships 
            WHERE user_identifier = ? AND friend_identifier = ? AND status = 'BLOCKED'
        ''', (receiver_ident, sender_ident))
        
        is_blocked = cursor.fetchone()
        
        conn.close()
        
        # R16 要求：必须是好友 (ACCEPTED) 且 未被拉黑 
        if friendship and not is_blocked:
            return True
        else:
            return False