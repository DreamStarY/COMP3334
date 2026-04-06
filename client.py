import tkinter as tk
from tkinter import ttk, messagebox, Toplevel, simpledialog
import requests
import uuid
import time
from datetime import datetime
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

API = "http://127.0.0.1:5000"

class SecureClient:
    def __init__(self, root):
        self.root = root
        self.root.title("COMP3334 安全客户端")
        self.root.geometry("420x580")

        self.private_key = None
        self.public_key = None
        self.current_user = ""
        self.saved_public_key = ""

        # 登录界面
        self.show_login_panel()

    # ====================== 登录界面 ======================
    def show_login_panel(self):
        self.clear_panel()

        ttk.Label(self.root, text="用户登录", font=("Arial",18,"bold")).pack(pady=12)
        
        ttk.Label(self.root, text="用户名").pack()
        self.e_user = ttk.Entry(self.root, width=35)
        self.e_user.pack(pady=4)

        ttk.Label(self.root, text="密码").pack()
        self.e_pw = ttk.Entry(self.root, show="*", width=35)
        self.e_pw.pack(pady=4)

        ttk.Label(self.root, text="OTP 验证码").pack()
        self.e_otp = ttk.Entry(self.root, width=35)
        self.e_otp.pack(pady=4)

        self.otp_display = ttk.Label(self.root, text="------", font=("Arial",26))
        self.otp_display.pack(pady=8)

        ttk.Button(self.root, text="登录", command=self.do_login, width=20).pack(pady=6)
        ttk.Button(self.root, text="注册新用户", command=self.show_register, width=20).pack(pady=2)

        self.refresh_otp_loop()

    # ====================== 注册界面 ======================
    def show_register(self):
        w = Toplevel(self.root)
        w.title("注册")
        w.geometry("350x280")

        ttk.Label(w, text="用户名").pack(pady=4)
        e_u = ttk.Entry(w, width=30)
        e_u.pack()

        ttk.Label(w, text="密码（>8位）").pack(pady=4)
        e_p = ttk.Entry(w, show="*", width=30)
        e_p.pack()

        def reg():
            u = e_u.get().strip()
            p = e_p.get().strip()
            if len(p) <=8:
                messagebox.showerror("错误","密码必须大于8位")
                return

            # 客户端本地生成密钥对
            pri, pub = self.gen_key()
            self.private_key = pri
            self.public_key = pub

            r = requests.post(API+"/register", json={
                "username":u,"password":p,"public_key":pub
            }).json()

            if r["status"]=="ok":
                messagebox.showinfo("成功","注册完成！私钥仅本地保存")
                w.destroy()
            else:
                messagebox.showerror("失败", r["msg"])

        ttk.Button(w, text="确认注册", command=reg).pack(pady=12)

    # ====================== 登录成功 → 功能界面 ======================
    def show_main_ui(self):
        self.clear_panel()
        ttk.Label(self.root, text=f"欢迎回来, {self.current_user}", font=("Arial",16,"bold")).pack(pady=10)

        ttk.Button(self.root, text="查看我的公钥", command=self.show_my_pubkey, width=25).pack(pady=6)
        ttk.Button(self.root, text="查看好友公钥", command=self.show_friend_pubkey, width=25).pack(pady=6)
        ttk.Button(self.root, text="检查密钥是否变更", command=self.check_key_change, width=25).pack(pady=6)
        
        # ========== Messaging ==========
        ttk.Label(self.root, text="消息", font=("Arial",12,"bold")).pack(pady=8)
        ttk.Button(self.root, text="给好友发消息", command=self.show_friends_list, width=25).pack(pady=4)
        ttk.Button(self.root, text="查看对话列表", command=self.show_conversation_list, width=25).pack(pady=4)
        
        # ========== Friend Management ==========
        ttk.Label(self.root, text="好友管理", font=("Arial",12,"bold")).pack(pady=8)
        ttk.Button(self.root, text="添加好友", command=self.add_friend, width=25).pack(pady=4)
        ttk.Button(self.root, text="查看待处理请求", command=self.view_pending_requests, width=25).pack(pady=4)
        ttk.Button(self.root, text="移除好友", command=self.remove_friend_ui, width=25).pack(pady=4)
        ttk.Button(self.root, text="拉黑用户", command=self.block_user_ui, width=25).pack(pady=4)
        
        ttk.Button(self.root, text="退出登录", command=self.do_logout, width=25).pack(pady=10)

    # ====================== 密钥相关 ======================
    def gen_key(self):
        pri = rsa.generate_private_key(65537, 2048)
        pub = pri.public_key()
        pub_pem = pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        return pri, pub_pem

    def show_my_pubkey(self):
        messagebox.showinfo("我的公钥", self.public_key[:100]+"...")

    def show_friend_pubkey(self):
        friend = simpledialog.askstring("输入","好友用户名：")
        if not friend: return
        r = requests.post(API+"/get-public-key", json={"username":friend}).json()
        pk = r.get("public_key","未找到")
        messagebox.showinfo(f"{friend} 的公钥", pk[:100]+"...")

    def check_key_change(self):
        r = requests.post(API+"/get-public-key", json={"username":self.current_user}).json()
        current = r.get("public_key","")
        if current != self.saved_public_key:
            messagebox.showwarning("警告","密钥已变更！")
        else:
            messagebox.showinfo("正常","密钥未变更")

    # ====================== 好友管理相关 ======================
    def add_friend(self):
        target = simpledialog.askstring("添加好友", "输入好友用户名、邮箱或联系码：")
        if not target:
            return
        try:
            r = requests.post(API+"/send-friend-request", json={
                "sender_id": self.current_user,
                "target_info": target
            }).json()
            if r["status"] == "success":
                messagebox.showinfo("成功", r["message"])
            else:
                messagebox.showerror("失败", r["message"])
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def view_pending_requests(self):
        try:
            r = requests.post(API+"/get-pending-requests", json={
                "my_identifier": self.current_user
            }).json()
            incoming = r.get("incoming", [])
            outgoing = r.get("outgoing", [])
            
            msg = "待处理的好友请求\n\n"
            msg += f"发给我的请求 ({len(incoming)}):\n"
            msg += "\n".join(incoming) if incoming else "无"
            msg += f"\n\n我发出的请求 ({len(outgoing)}):\n"
            msg += "\n".join(outgoing) if outgoing else "无"
            
            messagebox.showinfo("待处理请求", msg)
            
            # Offer to accept/decline incoming requests
            if incoming:
                self.handle_incoming_request(incoming[0])
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def handle_incoming_request(self, sender):
        result = messagebox.askyesno("好友请求", f"接受来自 {sender} 的好友请求吗？")
        action = "ACCEPTED" if result else "DECLINED"
        try:
            r = requests.post(API+"/respond-to-request", json={
                "my_identifier": self.current_user,
                "sender_identifier": sender,
                "action": action
            }).json()
            if r["success"]:
                messagebox.showinfo("成功", f"已{action}")
            else:
                messagebox.showerror("失败", "操作失败")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def remove_friend_ui(self):
        target = simpledialog.askstring("移除好友", "输入要移除的好友用户名：")
        if not target:
            return
        try:
            r = requests.post(API+"/remove-friend", json={
                "my_identifier": self.current_user,
                "target_identifier": target
            }).json()
            if r["success"]:
                messagebox.showinfo("成功", f"已移除好友 {target}")
            else:
                messagebox.showerror("失败", "移除失败")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def block_user_ui(self):
        target = simpledialog.askstring("拉黑用户", "输入要拉黑的用户名：")
        if not target:
            return
        try:
            r = requests.post(API+"/block-user", json={
                "my_identifier": self.current_user,
                "target_identifier": target
            }).json()
            if r["success"]:
                messagebox.showinfo("成功", f"已拉黑 {target}")
            else:
                messagebox.showerror("失败", "拉黑失败")
        except Exception as e:
            messagebox.showerror("错误", str(e))

    # ====================== 登录逻辑 ======================
    def do_login(self):
        u = self.e_user.get().strip()
        p = self.e_pw.get().strip()
        o = self.e_otp.get().strip()

        r = requests.post(API+"/login", json={"username":u,"password":p,"otp":o}).json()
        if r["status"]!="ok":
            messagebox.showerror("失败", r["msg"])
            return

        if self.saved_public_key and self.saved_public_key != r["public_key"]:
            messagebox.showwarning("警告","公钥已变更！可能存在风险！")

        self.saved_public_key = r["public_key"]
        self.current_user = u
        queued_delivered = r.get("queued_delivered", 0)
        if queued_delivered:
            messagebox.showinfo("消息已接收", f"登录时已接收 {queued_delivered} 条离线消息。")
        self.show_main_ui()

    # ====================== 工具 ======================
    def do_logout(self):
        if self.current_user:
            try:
                requests.post(API+"/logout", json={"username": self.current_user})
            except:
                pass
            self.current_user = ""
        self.clear_panel()
        self.show_login_panel()

    def clear_panel(self):
        for w in self.root.winfo_children():
            w.destroy()

    def refresh_otp_loop(self):
        try:
            otp = requests.post(API+"/get-otp").json()["otp"]
            self.otp_display.config(text=otp)
        except:
            self.otp_display.config(text="错误")
        self.root.after(180000, self.refresh_otp_loop)

    # ====================== 消息相关 ======================
    def show_friends_list(self):
        """Show list of accepted friends to choose who to message"""
        try:
            r = requests.post(API+"/get-accepted-friends", json={
                "user": self.current_user
            }).json()
            
            if r["status"] != "ok":
                messagebox.showerror("错误", r.get("message", "获取好友列表失败"))
                return
            
            friends = r.get("friends", [])
            
            if not friends:
                messagebox.showinfo("好友列表", "暂无好友。\n请先添加好友，然后开始对话。")
                return
            
            # Show friends list in a new window
            friends_win = Toplevel(self.root)
            friends_win.title("好友列表")
            friends_win.geometry("350x400")
            
            ttk.Label(friends_win, text="选择好友开始对话", font=("Arial",12,"bold")).pack(pady=8)
            ttk.Label(friends_win, text="点击好友姓名，然后点击'开始对话'", font=("Arial",9)).pack(pady=2)
            
            # Create frame with scrollbar
            frame = ttk.Frame(friends_win)
            frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            scrollbar = ttk.Scrollbar(frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, font=("Arial",10))
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)
            
            # Populate listbox with friends
            for friend in friends:
                listbox.insert(tk.END, friend)
            
            def start_chat():
                sel = listbox.curselection()
                if not sel:
                    messagebox.showwarning("提示", "请选择一个好友")
                    return
                friend = friends[sel[0]]
                friends_win.destroy()
                self.open_chat_window(friend)
            
            ttk.Button(friends_win, text="开始对话", command=start_chat, width=20).pack(pady=8)
            
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def show_conversation_list(self):
        """Show all conversations with most recent first"""
        try:
            r = requests.post(API+"/get-conversation-list", json={
                "user": self.current_user
            }).json()
            
            if r["status"] != "ok":
                messagebox.showerror("错误", r.get("message", "获取对话列表失败"))
                return
            
            conversations = r.get("conversations", [])
            
            if not conversations:
                messagebox.showinfo("对话列表", "暂无对话")
                return
            
            # Show conversation list in a new window
            conv_win = Toplevel(self.root)
            conv_win.title("对话列表 - 未读消息提醒")
            conv_win.geometry("450x400")
            
            ttk.Label(conv_win, text="对话列表（最近在前）", font=("Arial",12,"bold")).pack(pady=8)
            ttk.Label(conv_win, text="[数字]表示未读消息数量", font=("Arial",9)).pack(pady=2)
            
            # Create frame with scrollbar
            frame = ttk.Frame(conv_win)
            frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
            
            scrollbar = ttk.Scrollbar(frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            listbox = tk.Listbox(frame, yscrollcommand=scrollbar.set, font=("Arial",10))
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)
            
            # Populate listbox
            # R24 Unread count
            for conv in conversations:
                contact = conv["contact"]
                last_time_value = conv.get("last_time")
                if isinstance(last_time_value, int):
                    last_time = datetime.fromtimestamp(last_time_value).strftime("%Y-%m-%d %H:%M")
                elif isinstance(last_time_value, str) and last_time_value:
                    last_time = last_time_value[:16]
                else:
                    last_time = "N/A"
                unread_count = conv.get("unread_count", 0)
                unread_text = f" [{unread_count}]" if unread_count > 0 else ""
                listbox.insert(tk.END, f"{contact}{unread_text} ({last_time})")
            
            def open_chat():
                sel = listbox.curselection()
                if not sel:
                    messagebox.showwarning("提示", "请选择一个对话")
                    return
                contact = conversations[sel[0]]["contact"]
                conv_win.destroy()
                self.open_chat_window(contact)
            
            ttk.Button(conv_win, text="打开对话", command=open_chat, width=20).pack(pady=8)
        except Exception as e:
            messagebox.showerror("错误", str(e))

    def open_chat_window(self, contact):
        """Open chat window with a specific contact"""
        chat_win = Toplevel(self.root)
        chat_win.title(f"与 {contact} 的对话")
        chat_win.geometry("500x650")  # Made taller for load more button
        
        ttk.Label(chat_win, text=f"与 {contact} 的对话", font=("Arial",12,"bold")).pack(pady=8)
        
        # Mark messages as read
        try:
            requests.post(API+"/mark-messages-read", json={
                "user": self.current_user,
                "contact": contact
            })
        except:
            pass  # Don't show error if marking read fails
        
        # Message display area
        frame = ttk.Frame(chat_win)
        frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        scrollbar = ttk.Scrollbar(frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        msg_text = tk.Text(frame, yscrollcommand=scrollbar.set, font=("Arial",9), state=tk.DISABLED, height=15)
        msg_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.config(command=msg_text.yview)
        
        # Load More button (initially hidden)
        load_more_btn = ttk.Button(frame, text="加载更多消息", command=lambda: self.load_more_messages(chat_win, msg_text, contact))
        # Don't pack it yet - will be shown when needed
        
        # Store pagination state
        chat_win.loaded_messages = []  # List of loaded message IDs
        chat_win.has_more = True
        chat_win.oldest_msg_id = None
        
        # Load initial message history
        self.load_messages(chat_win, msg_text, contact, load_more_btn)
        
        # Message input area
        input_frame = ttk.Frame(chat_win)
        input_frame.pack(fill=tk.BOTH, padx=5, pady=5)
        
        ttk.Label(input_frame, text="消息:").pack()
        msg_input = ttk.Entry(input_frame, width=50)
        msg_input.pack(pady=4)
        
        def send_msg():
            text = msg_input.get().strip()
            if not text:
                messagebox.showwarning("提示", "请输入消息")
                return
            
            try:
                msg_id = str(uuid.uuid4())
                r = requests.post(API+"/send-message", json={
                    "sender": self.current_user,
                    "recipient": contact,
                    "ciphertext": text,
                    "msg_id": msg_id,
                    "created_at": int(time.time())
                }).json()
                
                if r["status"] == "ok":
                    msg_input.delete(0, tk.END)
                    # Add to display immediately
                    msg_text.config(state=tk.NORMAL)
                    msg_text.insert(tk.END, f"[{self.current_user}]: {text}\n")
                    msg_text.config(state=tk.DISABLED)
                    msg_text.see(tk.END)
                else:
                    messagebox.showerror("失败", r.get("message", "发送失败"))
            except Exception as e:
                messagebox.showerror("错误", str(e))
        
        ttk.Button(input_frame, text="发送", command=send_msg, width=20).pack(pady=4)

    def load_messages(self, chat_win, msg_text, contact, load_more_btn, before_message_id=None):
        """Load messages for chat window with pagination support"""
        try:
            request_data = {
                "user": self.current_user,
                "contact": contact,
                "limit": 20  # Load 20 messages at a time
            }
            if before_message_id:
                request_data["before_message_id"] = before_message_id
            
            r = requests.post(API+"/get-messages", json=request_data).json()
            
            if r["status"] == "ok":
                messages = r.get("messages", [])
                has_more = r.get("has_more", False)
                
                if messages:
                    # Reverse to show oldest first
                    messages = list(reversed(messages))
                    
                    msg_text.config(state=tk.NORMAL)
                    
                    # If loading more (before_message_id exists), insert at beginning
                    if before_message_id:
                        # Store current content
                        current_content = msg_text.get("1.0", tk.END)
                        msg_text.delete("1.0", tk.END)
                        
                        # Add new messages at the beginning
                        for msg in messages:
                            sender = msg["sender"]
                            timestamp_value = msg.get("timestamp")
                            if isinstance(timestamp_value, int):
                                timestamp = datetime.fromtimestamp(timestamp_value).strftime("%Y-%m-%d %H:%M")
                            elif isinstance(timestamp_value, str) and timestamp_value:
                                timestamp = timestamp_value[:16]
                            else:
                                timestamp = ""
                            ciphertext_preview = msg["ciphertext"][:50] if msg["ciphertext"] else ""
                            msg_text.insert("1.0", f"[{timestamp}] {sender}: {ciphertext_preview}...\n")
                        
                        # Add back the old content
                        msg_text.insert(tk.END, current_content)
                    else:
                        # Initial load - add messages at the end
                        for msg in messages:
                            sender = msg["sender"]
                            timestamp_value = msg.get("timestamp")
                            if isinstance(timestamp_value, int):
                                timestamp = datetime.fromtimestamp(timestamp_value).strftime("%Y-%m-%d %H:%M")
                            elif isinstance(timestamp_value, str) and timestamp_value:
                                timestamp = timestamp_value[:16]
                            else:
                                timestamp = ""
                            ciphertext_preview = msg["ciphertext"][:50] if msg["ciphertext"] else ""
                            msg_text.insert(tk.END, f"[{timestamp}] {sender}: {ciphertext_preview}...\n")
                        
                        msg_text.see(tk.END)  # Scroll to bottom for initial load
                    
                    msg_text.config(state=tk.DISABLED)
                    
                    # Update pagination state
                    chat_win.has_more = has_more
                    if messages:
                        chat_win.oldest_msg_id = messages[0]["msg_id"]  # First message is oldest
                    
                    # Show/hide load more button
                    if has_more and not before_message_id:
                        load_more_btn.pack(side=tk.BOTTOM, pady=5)
                    elif before_message_id:
                        # If we just loaded more, keep the button if there's still more
                        if has_more:
                            load_more_btn.pack(side=tk.BOTTOM, pady=5)
                        else:
                            load_more_btn.pack_forget()
                else:
                    # No messages loaded
                    if not before_message_id:  # Only for initial load
                        load_more_btn.pack_forget()
                        
        except Exception as e:
            if not before_message_id:  # Only show error for initial load
                pass  # If no messages yet, that's fine

        # R25  incremental loading 

    def load_more_messages(self, chat_win, msg_text, contact):
        """Load older messages when Load More button is clicked"""
        if not hasattr(chat_win, 'oldest_msg_id') or not chat_win.oldest_msg_id or not chat_win.has_more:
            return
            
        # Find the load more button
        load_more_btn = None
        for child in chat_win.winfo_children():
            if isinstance(child, ttk.Frame):
                for subchild in child.winfo_children():
                    if isinstance(subchild, ttk.Button) and subchild.cget("text") in ["加载更多消息", "加载中..."]:
                        load_more_btn = subchild
                        break
                if load_more_btn:
                    break
        
        if load_more_btn:
            load_more_btn.config(state="disabled", text="加载中...")
        
        # Load more messages
        self.load_messages(chat_win, msg_text, contact, load_more_btn or ttk.Button(), chat_win.oldest_msg_id)
        
        # Re-enable the button
        if load_more_btn:
            load_more_btn.config(state="normal", text="加载更多消息")

def run_client():
    root = tk.Tk()
    SecureClient(root)
    root.mainloop()