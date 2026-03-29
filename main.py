import threading
from server import run_server
from ui import run_ui

if __name__ == "__main__":
    threading.Thread(target=run_server, daemon=True).start()
    run_ui()