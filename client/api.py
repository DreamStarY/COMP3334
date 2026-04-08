from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx


class APIError(RuntimeError):
    def __init__(self, message: str, status_code: int = 0, payload: dict[str, Any] | None = None):
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.payload = payload or {}


class ServerAPI:
    def __init__(
        self,
        base_url: str,
        verify: bool | str = True,
        timeout: float = 10.0,
    ):
        self.base_url = base_url.rstrip("/")
        self.verify = str(Path(verify)) if isinstance(verify, Path) else verify
        self.timeout = timeout
        self.token: str | None = None
        self._client: httpx.AsyncClient | None = None

    async def __aenter__(self):
        await self.start()
        return self

    async def __aexit__(self, *exc_info):
        await self.close()

    async def start(self) -> None:
        if self._client is None:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                verify=self.verify,
                timeout=self.timeout,
                headers={"Accept": "application/json"},
            )

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    def set_token(self, token: str | None) -> None:
        self.token = token

    def _headers(self) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        return headers

    async def _request(self, method: str, path: str, **kwargs: Any) -> dict[str, Any]:
        await self.start()
        assert self._client is not None
        headers = kwargs.pop("headers", {})
        headers.update(self._headers())
        response = await self._client.request(method, path, headers=headers, **kwargs)
        try:
            data = response.json()
        except Exception as exc:
            raise APIError(f"服务器返回了无法解析的响应: HTTP {response.status_code}", response.status_code) from exc
        if response.status_code >= 400 or not data.get("ok", False):
            raise APIError(data.get("error", f"HTTP {response.status_code}"), response.status_code, data)
        return data

    async def health(self) -> dict[str, Any]:
        return await self._request("GET", "/api/health")

    async def register(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", "/api/auth/register", json=payload)

    async def login(self, username: str, password: str, otp: str) -> dict[str, Any]:
        return await self._request("POST", "/api/auth/login", json={"username": username, "password": password, "otp": otp})

    async def logout(self) -> dict[str, Any]:
        return await self._request("POST", "/api/auth/logout")

    async def me(self) -> dict[str, Any]:
        return await self._request("GET", "/api/auth/me")

    async def rotate_keys(self, payload: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", "/api/account/rotate-keys", json=payload)

    async def search_users(self, query: str) -> dict[str, Any]:
        return await self._request("GET", "/api/users/search", params={"q": query})

    async def list_contacts(self) -> dict[str, Any]:
        return await self._request("GET", "/api/contacts/list")

    async def get_key_bundle(self, username: str) -> dict[str, Any]:
        return await self._request("GET", f"/api/contacts/key-bundle/{username}")

    async def send_friend_request(self, target_username: str) -> dict[str, Any]:
        return await self._request("POST", "/api/contacts/request", json={"target_username": target_username})

    async def list_friend_requests(self) -> dict[str, Any]:
        return await self._request("GET", "/api/contacts/requests")

    async def accept_request(self, request_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/api/contacts/request/{request_id}/accept")

    async def reject_request(self, request_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/api/contacts/request/{request_id}/reject")

    async def cancel_request(self, request_id: int) -> dict[str, Any]:
        return await self._request("POST", f"/api/contacts/request/{request_id}/cancel")

    async def block_contact(self, username: str) -> dict[str, Any]:
        return await self._request("POST", "/api/contacts/block", json={"target_username": username})

    async def unblock_contact(self, username: str) -> dict[str, Any]:
        return await self._request("POST", "/api/contacts/unblock", json={"target_username": username})

    async def remove_contact(self, username: str) -> dict[str, Any]:
        return await self._request("POST", "/api/contacts/remove", json={"target_username": username})

    async def send_message(self, envelope: dict[str, Any]) -> dict[str, Any]:
        return await self._request("POST", "/api/messages/send", json={"envelope": envelope})

    async def sync_messages(self, limit: int = 50) -> dict[str, Any]:
        return await self._request("GET", "/api/messages/sync", params={"limit": limit})

    async def ack_delivered(self, message_ids: list[str]) -> dict[str, Any]:
        return await self._request("POST", "/api/messages/ack-delivered", json={"message_ids": message_ids})
