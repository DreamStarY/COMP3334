from enum import Enum
import time

# ==========================================
# (R17) Minimum delivery states
# ==========================================

class DeliveryState(Enum):
    PENDING = 0     # 初始状态：客户端准备/正在发送
    SENT = 1        # [R17] 已发送：客户端已成功将消息提交给服务器
    DELIVERED = 2   # [R17/R18 Option B] 已送达：收到对端客户端发来的 E2EE 确认回执

class Message:
    def __init__(self, msg_id: str, sender_id: str, recipient_id: str, ciphertext: bytes, is_ack: bool = False, ack_msg_id: str = None):
        self.msg_id = msg_id
        self.sender_id = sender_id
        self.recipient_id = recipient_id
        self.ciphertext = ciphertext  # HbC 模式下，服务器只能接触到密文
        self.status = DeliveryState.PENDING
        self.timestamp = time.time()
        
        # [R18 Option B 专用字段] 用于接收方返回 E2EE 确认回执
        self.is_ack = is_ack
        self.ack_msg_id = ack_msg_id

class HbCServer:
    def __init__(self):
        # 接收方消息队列：用于缓存接收方尚未拉取的消息
        self.message_queues = {} 

    def receive_from_sender(self, message: Message) -> dict:
        """
        服务器接收发送方的消息（包含普通消息和 ACK 回执），并放入接收方的缓存队列中。
        """
        if message.recipient_id not in self.message_queues:
            self.message_queues[message.recipient_id] = []
        
        # 将密文存入队列
        self.message_queues[message.recipient_id].append(message)
        
        # 返回服务器级别的 ACK 给发送方
        return {
            "status": "success", 
            "msg_id": message.msg_id
        }

class MessageManager:
    """
    负责处理本地消息收发与状态流转的管理器
    """
    def __init__(self, client_id: str, server: HbCServer):
        self.client_id = client_id
        self.server = server
        self.local_store = {} # 客户端本地的消息存储

    def send_message(self, recipient_id: str, ciphertext: bytes) -> Message:
        """
        发送方客户端发送普通消息。
        """
        msg_id = f"msg_{int(time.time()*1000)}"
        new_msg = Message(msg_id, self.client_id, recipient_id, ciphertext)
        self.local_store[msg_id] = new_msg

        # 1. 客户端将消息提交给服务器
        response = self.server.receive_from_sender(new_msg)

        if response.get("status") == "success":
            # 2. (R17) 触发 Sent 状态：提交给服务器即为 Sent
            self.local_store[msg_id].status = DeliveryState.SENT
                
        return new_msg

    # ==========================================
    # (R18 Option B) Stronger semantics (E2EE ACK)
    # ==========================================
    def send_e2ee_ack(self, received_msg: Message):
        """
        接收方专用：收到别人发来的普通消息后，生成并发送一个 ACK 回执给发送方
        """
        ack_ciphertext = b"encrypted_ack" # E2EE 协议下，这里需要用原发送方的公钥加密
        ack_msg = Message(
            msg_id=f"ack_{int(time.time()*1000)}",
            sender_id=self.client_id,
            recipient_id=received_msg.sender_id, # 接收方变为现在的发送方
            ciphertext=ack_ciphertext,
            is_ack=True,
            ack_msg_id=received_msg.msg_id
        )
        
        # 核心修改：直接调用服务器接口，将这个 ACK 作为一条特殊消息投递回服务器
        self.server.receive_from_sender(ack_msg)
        return ack_msg 

    def process_incoming_ack(self, ack_msg: Message):
        """
        发送方专用：当客户端从服务器拉取到对端发来的 ACK 回执时，调用此函数将原消息标为 Delivered
        """
        if ack_msg.is_ack and ack_msg.ack_msg_id in self.local_store:
            self.local_store[ack_msg.ack_msg_id].status = DeliveryState.DELIVERED