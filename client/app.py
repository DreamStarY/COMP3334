from __future__ import annotations

import argparse
import asyncio
import atexit
import secrets
import threading
import time
from collections import deque
from concurrent.futures import Future
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, TypeVar
from urllib.parse import urlencode

from flask import Flask, flash, redirect, render_template, request, session, url_for

from client.service import DEFAULT_STATE_ROOT, DEFAULT_TLS_CERT, SecureChatService
from common.crypto import format_fingerprint

T = TypeVar("T")


class ServiceBridge:
    """Run the async SecureChatService on a dedicated event loop thread.

    The web UI itself stays synchronous and simple, while all existing async
    httpx-based service calls continue to work unchanged on a single loop.
    """

    def __init__(self, server_url: str, tls_verify: bool | str, state_root: Path):
        self.service = SecureChatService(server_url=server_url, tls_verify=tls_verify, state_root=state_root)
        self.loop = asyncio.new_event_loop()
        self.thread = threading.Thread(target=self._run_loop, daemon=True, name="securechat-webui-loop")
        self.thread.start()
        self._event_log: deque[dict[str, str]] = deque(maxlen=80)
        self.last_sync_result: dict[str, Any] = {"summary": "尚未同步", "warnings": [], "new_messages": 0, "status_updates": []}
        self._last_sync_monotonic = 0.0
        self.call(self.service.start())
        self.log("本地 Web UI 客户端已启动")

    def _run_loop(self) -> None:
        asyncio.set_event_loop(self.loop)
        self.loop.run_forever()

    def call(self, coro: Any) -> Any:
        future = asyncio.run_coroutine_threadsafe(coro, self.loop)
        return future.result()

    def run_sync(self, func: Callable[[], T]) -> T:
        future: Future[T] = Future()

        def wrapper() -> None:
            try:
                result = func()
            except Exception as exc:  # pragma: no cover - bridged to caller
                future.set_exception(exc)
            else:
                future.set_result(result)

        self.loop.call_soon_threadsafe(wrapper)
        return future.result()

    def log(self, message: str) -> None:
        self._event_log.appendleft(
            {
                "at": time.strftime("%Y-%m-%d %H:%M:%S", time.localtime()),
                "message": message,
            }
        )

    def recent_events(self) -> list[dict[str, str]]:
        return list(self._event_log)

    def is_logged_in(self) -> bool:
        return bool(self.run_sync(lambda: self.service.username is not None))

    def username(self) -> str | None:
        return self.run_sync(lambda: self.service.username)

    def maybe_sync(self, force: bool = False) -> dict[str, Any]:
        if not self.is_logged_in():
            return self.last_sync_result
        now = time.monotonic()
        if not force and now - self._last_sync_monotonic < 2.0:
            return self.last_sync_result
        result = self.call(self.service.sync_once())
        for warning in result.get("warnings", []):
            self.log(f"警告: {warning}")
        if result.get("new_messages") or result.get("status_updates") or force:
            self.log(result.get("summary", "已同步"))
        self.last_sync_result = result
        self._last_sync_monotonic = now
        return result

    def shutdown(self) -> None:
        try:
            self.call(self.service.close())
        except Exception:
            pass
        if self.loop.is_running():
            self.loop.call_soon_threadsafe(self.loop.stop)
        if self.thread.is_alive():
            self.thread.join(timeout=2.0)


@dataclass(slots=True)
class DashboardState:
    contacts: list[dict[str, Any]]
    selected_peer: str
    selected_contact: dict[str, Any] | None
    messages: list[dict[str, Any]]
    incoming_requests: list[dict[str, Any]]
    outgoing_requests: list[dict[str, Any]]
    search_query: str
    search_results: list[str]
    page_offset: int
    page_limit: int
    last_sync: dict[str, Any]
    event_log: list[dict[str, str]]
    local_fingerprint: str
    username: str
    server_url: str
    has_more_history: bool



def build_redirect(endpoint: str, **params: Any):
    filtered = {k: v for k, v in params.items() if v not in (None, "", [])}
    return redirect(url_for(endpoint) + (f"?{urlencode(filtered)}" if filtered else ""))



def collect_dashboard_state(bridge: ServiceBridge, search_query: str, peer: str, offset: int, limit: int) -> DashboardState:
    bridge.maybe_sync(force=False)
    contacts = bridge.run_sync(lambda: bridge.service.list_local_contacts())
    peers = {item["username"] for item in contacts}
    if not peer and contacts:
        peer = contacts[0]["username"]
    if peer and peer not in peers:
        peer = ""
    if peer:
        messages = bridge.run_sync(lambda: bridge.service.list_messages(peer, limit=limit, offset=offset))
        selected_contact = bridge.run_sync(lambda: bridge.service.get_contact(peer))
        has_more_history = len(messages) == limit
    else:
        messages = []
        selected_contact = None
        has_more_history = False
    if search_query:
        search_results = bridge.call(bridge.service.search_users(search_query))
    else:
        search_results = []
    incoming = bridge.run_sync(lambda: bridge.service.pending_requests.get("incoming", []))
    outgoing = bridge.run_sync(lambda: bridge.service.pending_requests.get("outgoing", []))
    return DashboardState(
        contacts=contacts,
        selected_peer=peer,
        selected_contact=selected_contact,
        messages=messages,
        incoming_requests=incoming,
        outgoing_requests=outgoing,
        search_query=search_query,
        search_results=search_results,
        page_offset=offset,
        page_limit=limit,
        last_sync=bridge.last_sync_result,
        event_log=bridge.recent_events(),
        local_fingerprint=format_fingerprint(bridge.run_sync(lambda: bridge.service.local_fingerprint())),
        username=bridge.username() or "",
        server_url=bridge.run_sync(lambda: bridge.service.server_url),
        has_more_history=has_more_history,
    )



def create_web_app(server_url: str, tls_verify: bool | str, state_root: Path, secret_key: str | None = None) -> Flask:
    app = Flask(
        __name__,
        template_folder=str(Path(__file__).resolve().parent / "templates"),
        static_folder=str(Path(__file__).resolve().parent / "static"),
    )
    app.config["SECRET_KEY"] = secret_key or secrets.token_hex(32)
    bridge = ServiceBridge(server_url=server_url, tls_verify=tls_verify, state_root=state_root)
    atexit.register(bridge.shutdown)
    app.config["BRIDGE"] = bridge
    app.config["PAGE_SIZE"] = 30

    @app.template_filter("fp")
    def _fp_filter(value: str | None) -> str:
        if not value:
            return "(none)"
        return format_fingerprint(value)

    def get_bridge() -> ServiceBridge:
        return app.config["BRIDGE"]

    def require_login() -> ServiceBridge:
        bridge_local = get_bridge()
        if not bridge_local.is_logged_in():
            raise RuntimeError("请先登录本地 Web UI 客户端")
        return bridge_local

    @app.get("/")
    def index():
        bridge_local = get_bridge()
        if bridge_local.is_logged_in():
            return redirect(url_for("dashboard"))
        return render_template(
            "auth.html",
            server_url=bridge_local.run_sync(lambda: bridge_local.service.server_url),
            state_root=str(state_root),
            registration_result=None,
            register_error=None,
            login_error=None,
        )

    @app.post("/register")
    def register():
        bridge_local = get_bridge()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        registration_result = None
        register_error = None
        try:
            registration_result = bridge_local.call(bridge_local.service.register(username, password))
            bridge_local.log(f"已注册用户 {username}")
            flash("注册成功。请将 OTP Secret 导入认证器后再登录。", "success")
        except Exception as exc:
            register_error = str(exc)
            flash(f"注册失败: {register_error}", "error")
        return render_template(
            "auth.html",
            server_url=bridge_local.run_sync(lambda: bridge_local.service.server_url),
            state_root=str(state_root),
            registration_result=registration_result,
            prefill_username=username,
            register_error=register_error,
            login_error=None,
        )

    @app.post("/login")
    def login():
        bridge_local = get_bridge()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        otp = request.form.get("otp", "").strip()
        login_error = None
        try:
            bridge_local.call(bridge_local.service.login(username, password, otp))
            bridge_local.log(f"已登录为 {username}")
            flash("登录成功。", "success")
            session["active_peer"] = ""
            return redirect(url_for("dashboard"))
        except Exception as exc:
            login_error = str(exc)
            flash(f"登录失败: {login_error}", "error")
            return render_template(
                "auth.html",
                server_url=bridge_local.run_sync(lambda: bridge_local.service.server_url),
                state_root=str(state_root),
                registration_result=None,
                prefill_username=username,
                register_error=None,
                login_error=login_error,
            )

    @app.post("/logout")
    def logout():
        bridge_local = get_bridge()
        if bridge_local.is_logged_in():
            try:
                bridge_local.call(bridge_local.service.logout())
                bridge_local.log("已登出")
                flash("已登出。", "success")
            except Exception as exc:
                flash(f"登出失败: {exc}", "error")
        session.clear()
        return redirect(url_for("index"))

    @app.get("/dashboard")
    def dashboard():
        try:
            bridge_local = require_login()
        except Exception as exc:
            flash(str(exc), "error")
            return redirect(url_for("index"))
        peer = request.args.get("peer", "").strip() or session.get("active_peer", "")
        search_query = request.args.get("search", "").strip()
        try:
            offset = max(int(request.args.get("offset", "0")), 0)
        except Exception:
            offset = 0
        limit = int(app.config["PAGE_SIZE"])
        state = collect_dashboard_state(bridge_local, search_query, peer, offset, limit)
        session["active_peer"] = state.selected_peer
        return render_template("dashboard.html", state=state)

    @app.post("/sync")
    def sync_now():
        bridge_local = require_login()
        peer = request.form.get("peer", "").strip() or session.get("active_peer", "")
        try:
            result = bridge_local.maybe_sync(force=True)
            for warning in result.get("warnings", []):
                flash(warning, "warning")
            flash(result.get("summary", "已同步"), "success")
        except Exception as exc:
            flash(f"同步失败: {exc}", "error")
        return build_redirect("dashboard", peer=peer)

    @app.post("/message/send")
    def send_message():
        bridge_local = require_login()
        peer = request.form.get("peer", "").strip()
        text = request.form.get("text", "").strip()
        raw_ttl = request.form.get("ttl_seconds", "").strip()
        ttl_seconds = None
        if raw_ttl:
            try:
                ttl_seconds = max(int(raw_ttl), 1)
            except Exception:
                flash("TTL 必须是正整数秒。", "error")
                return build_redirect("dashboard", peer=peer)
        try:
            bridge_local.call(bridge_local.service.send_text_message(peer, text, ttl_seconds))
            bridge_local.log(f"已向 {peer} 发送消息")
            flash("消息已发送。", "success")
        except Exception as exc:
            flash(f"发送失败: {exc}", "error")
        return build_redirect("dashboard", peer=peer)

    @app.post("/friends/request")
    def send_friend_request():
        bridge_local = require_login()
        target = request.form.get("target_username", "").strip()
        try:
            bridge_local.call(bridge_local.service.send_friend_request(target))
            bridge_local.log(f"已向 {target} 发送好友请求")
            flash(f"已向 {target} 发送好友请求。", "success")
        except Exception as exc:
            flash(f"发送好友请求失败: {exc}", "error")
        return build_redirect("dashboard", search=request.form.get("search_query", "").strip(), peer=session.get("active_peer", ""))

    @app.post("/requests/<int:request_id>/<action>")
    def request_action(request_id: int, action: str):
        bridge_local = require_login()
        try:
            if action == "accept":
                bridge_local.call(bridge_local.service.accept_request(request_id))
            elif action == "reject":
                bridge_local.call(bridge_local.service.reject_request(request_id))
            elif action == "cancel":
                bridge_local.call(bridge_local.service.cancel_request(request_id))
            else:
                raise ValueError("未知请求动作")
            bridge_local.log(f"好友请求 #{request_id} 已执行 {action}")
            flash(f"请求 #{request_id} 操作成功: {action}", "success")
        except Exception as exc:
            flash(f"请求操作失败: {exc}", "error")
        return build_redirect("dashboard", peer=session.get("active_peer", ""))

    @app.post("/contacts/<username>/<action>")
    def contact_action(username: str, action: str):
        bridge_local = require_login()
        try:
            if action == "block":
                bridge_local.call(bridge_local.service.block_contact(username))
            elif action == "unblock":
                bridge_local.call(bridge_local.service.unblock_contact(username))
            elif action == "remove":
                bridge_local.call(bridge_local.service.remove_contact(username))
            elif action == "verify":
                bridge_local.run_sync(lambda: bridge_local.service.verify_contact(username))
            elif action == "trust":
                bridge_local.run_sync(lambda: bridge_local.service.trust_new_key(username))
            else:
                raise ValueError("未知联系人动作")
            bridge_local.log(f"联系人 {username} 操作成功: {action}")
            flash(f"联系人 {username} 操作成功: {action}", "success")
        except Exception as exc:
            flash(f"联系人操作失败: {exc}", "error")
        return build_redirect("dashboard", peer=username)

    @app.post("/account/rotate-keys")
    def rotate_keys():
        bridge_local = require_login()
        password = request.form.get("password", "")
        peer = session.get("active_peer", "")
        try:
            result = bridge_local.call(bridge_local.service.rotate_keys(password))
            bridge_local.log("本机密钥已轮换")
            flash(f"本机密钥已轮换，新指纹: {format_fingerprint(result['key_fingerprint'])}", "warning")
        except Exception as exc:
            flash(f"轮换密钥失败: {exc}", "error")
        return build_redirect("dashboard", peer=peer)

    return app



def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="SecureChat Web UI Client")
    parser.add_argument("--server", default="https://127.0.0.1:5443", help="HTTPS server base URL")
    parser.add_argument("--cert", default=str(DEFAULT_TLS_CERT), help="TLS certificate path for server verification")
    parser.add_argument("--insecure", action="store_true", help="仅用于本地测试：跳过 TLS 证书验证")
    parser.add_argument("--state-root", default=str(DEFAULT_STATE_ROOT.with_name(".securechat_webui")), help="本地状态目录")
    parser.add_argument("--host", default="127.0.0.1", help="本地 Web UI 监听地址")
    parser.add_argument("--port", type=int, default=8501, help="本地 Web UI 监听端口")
    parser.add_argument("--secret-key", default="", help="可选：覆盖 Flask session secret")
    return parser



def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()
    verify: bool | str = False if args.insecure else args.cert
    app = create_web_app(
        server_url=args.server,
        tls_verify=verify,
        state_root=Path(args.state_root),
        secret_key=args.secret_key or None,
    )
    app.run(host=args.host, port=args.port, debug=False)


if __name__ == "__main__":
    main()
