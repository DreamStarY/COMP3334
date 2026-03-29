import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
import requests
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
        ttk.Button(self.root, text="退出登录", command=self.show_login_panel, width=25).pack(pady=10)

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
        friend = tk.simpledialog.askstring("输入","好友用户名：")
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
        self.show_main_ui()

    # ====================== 工具 ======================
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

def run_client():
    root = tk.Tk()
    SecureClient(root)
    root.mainloop()