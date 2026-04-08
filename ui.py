import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
import requests
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import serialization
import base64

API = "http://127.0.0.1:5000"

class AuthUI:
    def __init__(self, root):
        self.root = root
        self.root.title("登录系统")
        self.root.geometry("380x480")

        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()

        ttk.Label(root, text="用户登录", font=("Arial", 16, "bold")).pack(pady=10)

        ttk.Label(root, text="用户名").pack()
        self.user_entry = ttk.Entry(root, width=32)
        self.user_entry.pack(pady=4)

        ttk.Label(root, text="密码").pack()
        self.pw_entry = ttk.Entry(root, show="*", width=32)
        self.pw_entry.pack(pady=4)

        ttk.Button(root, text="登录", command=self.login, width=20).pack(pady=6)
        ttk.Button(root, text="注册新用户", command=self.open_register, width=20).pack(pady=2)

    def login(self):
        u = self.user_entry.get().strip()
        p = self.pw_entry.get().strip()
        if not u or not p:
            messagebox.showwarning("提示", "请填写完整")
            return
        try:
            r = requests.post(API + "/login", json={"username": u, "password": p})
            d = r.json()
            if d["status"] == "ok":
                server_public_key = serialization.load_pem_public_key(d["public_key"].encode('utf-8'))
                shared_key = self.private_key.exchange(server_public_key)
                messagebox.showinfo("成功", d["msg"])
                self.root.destroy()
            else:
                messagebox.showerror("失败", d["msg"])
        except Exception as e:
            messagebox.showerror("错误", f"服务未启动: {e}")

    def open_register(self):
        win = Toplevel(self.root)
        win.title("用户注册")
        win.geometry("360x260")
        win.grab_set()

        ttk.Label(win, text="新用户注册", font=("Arial",14,"bold")).pack(pady=10)
        ttk.Label(win, text="用户名").pack()
        e_user = ttk.Entry(win, width=30)
        e_user.pack(pady=3)

        ttk.Label(win, text="密码").pack()
        e_pw = ttk.Entry(win, show="*", width=30)
        e_pw.pack(pady=3)

        def do_register():
            u = e_user.get().strip()
            p = e_pw.get().strip()
            if not u or not p:
                messagebox.showwarning("提示", "请填写完整")
                return
            try:
                r = requests.post(API + "/register", json={"username": u, "password": p})
                d = r.json()
                if d["status"] == "ok":
                    messagebox.showinfo("成功", "注册成功！")
                    win.destroy()
                else:
                    messagebox.showerror("失败", d["msg"])
            except Exception as e:
                messagebox.showerror("错误", f"服务异常: {e}")

        ttk.Button(win, text="确认注册", command=do_register, width=20).pack(pady=10)

def run_ui():
    root = tk.Tk()
    app = AuthUI(root)
    root.mainloop()