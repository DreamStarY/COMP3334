import tkinter as tk
from tkinter import ttk, messagebox, Toplevel
import requests

API = "http://127.0.0.1:5000"

class AuthUI:
    def __init__(self, root):
        self.root = root
        self.root.title("登录系统")
        self.root.geometry("380x480")

        ttk.Label(root, text="用户登录", font=("Arial", 16, "bold")).pack(pady=10)

        ttk.Label(root, text="用户名").pack()
        self.user_entry = ttk.Entry(root, width=32)
        self.user_entry.pack(pady=4)

        ttk.Label(root, text="密码").pack()
        self.pw_entry = ttk.Entry(root, show="*", width=32)
        self.pw_entry.pack(pady=4)

        ttk.Label(root, text="一次性密码").pack()
        self.otp_entry = ttk.Entry(root, width=32)
        self.otp_entry.pack(pady=4)

        ttk.Button(root, text="登录", command=self.login, width=20).pack(pady=6)
        ttk.Button(root, text="注册新用户", command=self.open_register, width=20).pack(pady=2)

        ttk.Label(root, text="当前随机 OTP", font=("Arial", 12, "bold")).pack(pady=12)
        self.otp_display = ttk.Label(root, text="------", font=("Arial", 28, "bold"))
        self.otp_display.pack()

        # 启动立即刷新
        self.refresh_otp()
        # 3分钟自动刷新
        self.root.after(180000, self.loop_otp)

    def loop_otp(self):
        self.refresh_otp()
        self.root.after(180000, self.loop_otp)

    def refresh_otp(self):
        try:
            r = requests.post(API + "/get-otp")
            otp = r.json().get("otp")
            self.otp_display.config(text=otp)
        except:
            self.otp_display.config(text="错误")

    def login(self):
        u = self.user_entry.get().strip()
        p = self.pw_entry.get().strip()
        o = self.otp_entry.get().strip()
        if not u or not p or not o:
            messagebox.showwarning("提示", "请填写完整")
            return
        try:
            r = requests.post(API + "/login", json={
                "username": u,
                "password": p,
                "otp": o
            })
            d = r.json()
            if d["status"] == "ok":
                messagebox.showinfo("成功", d["msg"])
            else:
                messagebox.showerror("失败", d["msg"])
        except:
            messagebox.showerror("错误", "服务未启动")

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
                messagebox.showwarning("提示", "请输入完整")
                return
            try:
                r = requests.post(API+"/register", json={"username":u,"password":p})
                d = r.json()
                if d["status"] == "ok":
                    messagebox.showinfo("成功", "注册成功！")
                    win.destroy()
                else:
                    messagebox.showerror("失败", d["msg"])
            except:
                messagebox.showerror("错误", "服务异常")

        ttk.Button(win, text="确认注册", command=do_register, width=20).pack(pady=10)

def run_ui():
    root = tk.Tk()
    app = AuthUI(root)
    root.mainloop()