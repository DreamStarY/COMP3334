# test.py
import requests

# 注册用户
res = requests.post("http://127.0.0.1:5000/register", 
    json={"username": "alice", "password": "123456"})
print(res.json())