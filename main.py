import threading
import time
import server
import client

if __name__ == "__main__":
    # 启动后端服务
    threading.Thread(target=server.run_server, daemon=True).start()
    time.sleep(1)  # 等待服务启动

    # 启动客户端UI
    client.run_client()