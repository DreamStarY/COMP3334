# COMP3334 SecureChat (Flask + SQLite + Web UI)

一个满足 COMP3334 项目要求的端到端加密（E2EE）1 对 1 即时通讯原型系统。

## 技术栈

| 用途 | 库 / 技术 | 说明 |
|---|---|---|
| 服务端框架 | Flask | 轻量、易部署、REST API 清晰 |
| 数据库 | SQLite | 单文件 `server.db`，便于提交与演示 |
| 前端 Web UI | Flask + Jinja2 | 浏览器界面简单完整，部署成本低 |
| HTTP 客户端 | httpx | 原生 async，复用现有客户端服务层 |
| 密码哈希 | bcrypt | 存储密码哈希 |
| OTP | pyotp | 登录第二因素 TOTP |
| E2EE 密码学 | cryptography | X25519 + Ed25519 + HKDF + AES-GCM |

---

## 已实现功能

- 用户注册
- 密码 + OTP 登录
- 登出 / token 失效
- 1 对 1 好友请求 / 接受 / 拒绝 / 取消
- 删除好友 / 拉黑 / 解除拉黑
- E2EE 私聊
- 定时自毁消息（TTL）
- 离线密文队列存储转发
- 消息状态：`sent`、`delivered`
- 会话列表与未读计数（客户端本地维护）
- 联系人身份指纹显示、手工验证、本地 trust-on-first-use
- 密钥变化检测与警告
- 重放去重（基于 `message_id` 持久化）
- TLS 传输保护（自签名证书，用于本地部署）
- 本地浏览器 Web UI（聊天、联系人、请求、安全与系统日志面板）

---

## 项目目录

```text
code/
├── client/
│   ├── app.py                # 本地 Web UI 客户端（Flask）
│   ├── api.py                # httpx 异步 API 客户端
│   ├── device_store.py       # 本地设备密钥安全存储
│   ├── local_store.py        # 本地 SQLite 状态/消息缓存
│   ├── service.py            # 客户端核心业务逻辑
│   ├── templates/            # Jinja2 模板
│   └── static/               # Web UI 样式文件
├── common/
│   ├── crypto.py             # 密钥、加密、签名、KDF 等
│   └── utils.py              # 通用辅助函数
├── server/
│   ├── app.py                # Flask 服务端
│   ├── config.py             # 配置
│   └── db.py                 # SQLite schema / helper
├── scripts/
│   └── generate_tls_cert.py  # 生成本地 TLS 证书
├── tests/
│   ├── smoke_test.py         # Flask test_client 级别测试
│   ├── service_integration.py# 真正的 httpx + TLS 集成测试
│   └── webui_smoke.py        # Web UI 登录/页面渲染冒烟测试
├── certs/
│   ├── localhost-cert.pem
│   └── localhost-key.pem
├── requirements.txt
└── server.db
```

---

## 架构说明

系统仍然保持“客户端负责 E2EE、服务器只转发密文”的架构。

### 服务端

- 使用 Flask 提供 HTTPS REST API。
- 保存用户账号、密码哈希、OTP secret、公钥、好友关系、离线密文队列和投递状态。
- 服务器永远不持有解密消息所需的私钥。

### 本地 Web UI 客户端

- 也是一个本地运行的 Flask 应用，但它**不是中心服务器的一部分**。
- 浏览器只作为简单界面层。
- 真正的 E2EE、私钥读取、签名、解密、重放保护、未读统计都在本地 Python 客户端逻辑中完成。
- 本地 Web UI 通过后台线程持有 `SecureChatService`，再用 `httpx` 与远端 Flask 服务器通信。

这意味着：

- 可以获得“简单但完整”的浏览器界面；
- 又不会把解密逻辑搬到服务器端；
- 课程要求的 HbC 服务器模型仍然成立。

---

## 协议概要

### 1. 身份与密钥

每个客户端本地生成并保存：

- Ed25519 长期签名密钥对
- X25519 长期密钥协商密钥对

服务器仅保存公钥：

- `signing_public_key`
- `exchange_public_key`
- `key_fingerprint = SHA-256(sign_pub || exchange_pub)`

### 2. 会话建立

当前项目采用**静态 X25519 + TOFU**：

- Alice 使用自己的 X25519 私钥和 Bob 的 X25519 公钥做 ECDH
- 用 HKDF-SHA256 派生 32 字节会话根密钥
- `session_id` 由双方用户名和双方 key fingerprint 派生

> 说明：该设计满足课程作业的 HbC 服务器模型与 E2EE 要求，但**不提供完整的双棘轮前向保密**。这在报告中有明确说明。

### 3. 消息加密

每条消息：

1. 使用 `message_id + counter + session_id` 派生消息密钥
2. 使用 AES-GCM 加密明文
3. 将 `sender / recipient / counter / session_id / TTL / expires_at` 放入认证附加数据（AD）
4. 使用 Ed25519 对消息封装再签名一次

### 4. 重放保护

客户端本地持久化：

- `seen_messages(msg_id)`
- 会话状态中的 `last_in_counter`

同一个 `message_id` 重复出现时会被忽略。

### 5. 密钥变化检测

客户端本地保存：

- `trusted_key_fingerprint`
- `current_key_fingerprint`

如果好友当前 fingerprint 与本地信任值不同：

- 标记 `key_changed = 1`
- 阻止自动解密新消息
- 阻止继续发送
- 需要用户在 Web UI 中手工“信任新密钥”

---

## 本地存储

### 服务端

- `server.db`：服务端 SQLite 单文件数据库

主要表：

- `users`
- `sessions`
- `friend_requests`
- `contacts`
- `messages`
- `status_updates`
- `rate_limits`

### 客户端

默认目录：

- Linux/macOS: `~/.securechat_webui/<username>/`
- Windows: `%USERPROFILE%\.securechat_webui\<username>\`

主要文件：

- `keystore.json`：用用户密码派生的密钥加密保存本地私钥
- `client_state.db`：本地联系人、消息、未读数、seen set

---

## 从零部署（Ubuntu 22.04 / 24.04）

### 1. 安装 Python

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv
```

### 2. 进入项目目录并创建虚拟环境

```bash
cd code
python3 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt
```

### 3. 生成 TLS 证书

```bash
python scripts/generate_tls_cert.py
```

### 4. 启动服务端

```bash
python -m server.app
```

默认监听：

- `https://127.0.0.1:5443`

### 5. 启动本地 Web UI 客户端

打开**另一个终端**：

```bash
cd code
source .venv/bin/activate
python -m client.app --server https://127.0.0.1:5443 --cert certs/localhost-cert.pem --port 8501
```

然后在浏览器打开：

- `http://127.0.0.1:8501`

### 6. 再启动第二个客户端（演示双用户）

再开一个终端：

```bash
cd code
source .venv/bin/activate
python -m client.app --server https://127.0.0.1:5443 --cert certs/localhost-cert.pem --port 8502 --state-root ~/.securechat_webui_bob
```

浏览器打开：

- `http://127.0.0.1:8502`

这样可以分别作为 Alice 和 Bob 的独立本地设备。

---

## 从零部署（Windows 11）

### 1. 安装 Python

- 下载安装 Python 3.11+ 或 3.12+ 或 3.13+
- 安装时勾选 **Add Python to PATH**

### 2. 在 PowerShell 中进入项目目录

```powershell
cd code
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. 生成 TLS 证书

```powershell
python scripts\generate_tls_cert.py
```

### 4. 启动服务端

```powershell
python -m server.app
```

### 5. 启动本地 Web UI 客户端

另开一个 PowerShell：

```powershell
cd code
.\.venv\Scripts\Activate.ps1
python -m client.app --server https://127.0.0.1:5443 --cert certs\localhost-cert.pem --port 8501
```

浏览器打开：

- `http://127.0.0.1:8501`

### 6. 第二个客户端示例

```powershell
cd code
.\.venv\Scripts\Activate.ps1
python -m client.app --server https://127.0.0.1:5443 --cert certs\localhost-cert.pem --port 8502 --state-root C:\securechat_webui_bob
```

---

## Web UI 使用说明

### 登录 / 注册页

- **注册**：输入用户名和密码后，系统会在本地生成身份密钥并返回 OTP Secret / Provisioning URI。
- **登录**：输入用户名、密码和认证器生成的 OTP 完成登录。

### Dashboard 页面

页面分为几块：

1. **会话列表**
   - 显示联系人、最近活动时间、未读数、已验证状态、密钥变化状态、blocked 状态。

2. **聊天区域**
   - 查看分页消息历史。
   - 发送普通消息或 TTL 自毁消息。
   - 查看 outgoing 消息的 `sent / delivered` 状态。

3. **好友请求区域**
   - 查看 incoming / outgoing 请求。
   - 接受、拒绝、取消请求。

4. **搜索与添加联系人**
   - 搜索用户名。
   - 向指定用户发送好友请求。

5. **联系人安全与管理**
   - 查看联系人当前指纹和已信任指纹。
   - 标记为已验证。
   - 在密钥变更后手工“信任新密钥”。
   - 拉黑 / 解除拉黑 / 删除好友。
   - 轮换本机密钥（用于演示 key-change warning）。

6. **System / Sync Log**
   - 查看同步摘要、警告、关键操作日志。

---

## 推荐演示流程

1. 启动服务端。
2. 分别启动 `8501` 和 `8502` 两个本地 Web UI 客户端。
3. 在两个浏览器窗口中分别注册 `alice` 和 `bob`。
4. 将注册时显示的 OTP Secret 导入认证器。
5. 分别登录 Alice 和 Bob。
6. Alice 搜索 Bob 并发送好友请求。
7. Bob 在“好友请求”区域接受。
8. Alice 选择 Bob，发送一条普通消息和一条带 TTL 的消息。
9. Bob 点击“立即同步”并查看消息送达。
10. Alice 再同步，观察消息状态变为 `delivered`。
11. 在“联系人安全与管理”中查看双方指纹。
12. 用 Bob 的“轮换本机密钥”触发 Alice 侧的 key-change warning。

---

## 运行测试

```bash
python -m tests.smoke_test
python -m tests.service_integration
python -m tests.webui_smoke
```

测试覆盖：

- 注册 / 登录 / 好友流程
- E2EE 发送与接收
- delivered 状态回执
- 密钥变更检测
- 消息篡改检测
- Web UI 登录与 dashboard 渲染

---

## 安全说明

- 所有客户端到服务器通信都通过 TLS。
- 私钥只保存在本地 `keystore.json` 中，并由用户密码派生的密钥加密。
- 服务器只保存公钥和密文，不保存明文聊天内容。
- TTL 由客户端写入认证附加数据，不能被服务器静默篡改。
- 重放保护依赖本地持久化 `message_id` 与计数器状态。
- delivered 状态会向服务器暴露接收方上线 / 同步时间，这是报告中已说明的元数据权衡。

---

## 备注

- 本项目是课程原型，不是生产级 Signal 替代品。
- 当前实现是单设备模型，不支持多设备同步。
- 使用静态 X25519 + TOFU，未实现完整双棘轮与前向保密恢复。
