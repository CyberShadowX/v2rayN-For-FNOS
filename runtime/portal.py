"""Authenticated HTTPS entry for the native desktop and its fixed supervisor API."""
from __future__ import annotations

import argparse
import asyncio
from collections import defaultdict, deque
from contextlib import suppress
from dataclasses import dataclass, field
import hashlib
import hmac
import ipaddress
import json
from pathlib import Path
import secrets
import ssl
import sys
import time
from urllib.parse import urlsplit

from aiohttp import WSMsgType, web

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from runtime.credentials import (CredentialError, credential_revision, read_portal_config,
                                 validate_current_password, validate_new_password)

SESSION_SECONDS = 8 * 60 * 60
MAX_IMPORT_BYTES = 1024 * 1024
MAX_CONTROL_REPLY = 128 * 1024
WEB_ROOT = Path(__file__).resolve().parent.parent / "web"
ICON_ROOT = WEB_ROOT.parent / "ui" / "images"
NOVNC_ROOT = Path("/usr/share/novnc")
PUBLIC_STATUS = frozenset({"app", "title", "version", "gui_running", "network_active",
                           "network_owner", "updating", "last_update", "message", "network_phase",
                           "network_cleanup_verified", "network_needs_recovery", "network_error"})
ACTIONS = frozenset({"check_update", "update", "restart", "network_on", "network_off",
                     "rollback", "import"})
ALLOWED_PEERS = tuple(ipaddress.ip_network(value) for value in (
    "127.0.0.0/8", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10",
    "::1/128", "fc00::/7",
))


@dataclass
class Session:
    csrf: str
    expires: float
    sockets: set = field(default_factory=set)


class SupervisorError(Exception):
    pass


class Portal:
    def __init__(self, state: Path, title: str, vnc_port: int):
        self.state = state.resolve()
        config = read_portal_config(self.state / "portal.json")
        self.app_id = config["app"]
        if self.app_id not in {"v2rayn", "clash"}:
            raise ValueError("Unknown native application")
        self.title = str(title or config.get("title") or self.app_id)[:120]
        self.salt = bytes.fromhex(config["password_salt"])
        self.password_hash = bytes.fromhex(config["password_hash"])
        self.vnc_password = config["vnc_password"]
        if not 16 <= len(self.salt) <= 64 or len(self.password_hash) != 32:
            raise ValueError("Invalid portal authentication configuration")
        if not isinstance(self.vnc_password, str) or len(self.vnc_password.encode("ascii")) != 8:
            raise ValueError("Invalid VNC authentication configuration")
        if not 1 <= vnc_port <= 65535:
            raise ValueError("Invalid local VNC port")
        self.vnc_port = vnc_port
        # Cookies are scoped to hosts, not ports: use distinct names for both apps.
        self.cookie_name = f"fnos_native_proxy_{self.app_id}"
        self.sessions: dict[str, Session] = {}
        self.attempts: dict[str, deque] = defaultdict(deque)
        self.hash_slots = asyncio.Semaphore(2)
        self.auth_lock = asyncio.Lock()
        self.password_lock = asyncio.Lock()
        self.password_attempts: deque = deque()
        self.auth_revision = credential_revision(config)
        self.vnc_connections = 0

    async def sync_credentials(self):
        """Root resets take effect without restarting the desktop or networking."""
        async with self.auth_lock:
            try:
                config = await asyncio.to_thread(read_portal_config, self.state / "portal.json", self.app_id)
            except CredentialError:
                await self.drop_all_sessions()
                raise
            revision = credential_revision(config)
            if revision != self.auth_revision or config["vnc_password"] != self.vnc_password:
                self.salt = bytes.fromhex(config["password_salt"])
                self.password_hash = bytes.fromhex(config["password_hash"])
                self.vnc_password = config["vnc_password"]
                self.auth_revision = revision
                await self.drop_all_sessions()
                self.attempts.clear()
                self.password_attempts.clear()

    async def drop_all_sessions(self):
        await asyncio.gather(*(self.drop_session(token) for token in list(self.sessions)))

    def session(self, request: web.Request) -> Session | None:
        token = request.cookies.get(self.cookie_name, "")
        session = self.sessions.get(token)
        return session if session and session.expires > time.monotonic() else None

    def require_session(self, request: web.Request) -> Session:
        session = self.session(request)
        if session is None:
            raise web.HTTPUnauthorized(text=json.dumps({"error": "请先登录"}),
                                      content_type="application/json")
        return session

    @staticmethod
    def require_origin(request: web.Request) -> None:
        origin = request.headers.get("Origin", "")
        try:
            candidate = urlsplit(origin)
            expected = urlsplit(f"{request.scheme}://{request.host}")
            valid = (candidate.scheme == expected.scheme and candidate.hostname == expected.hostname
                     and (candidate.port or (443 if candidate.scheme == "https" else 80))
                     == (expected.port or (443 if expected.scheme == "https" else 80))
                     and not candidate.username and not candidate.password
                     and not candidate.path and not candidate.query and not candidate.fragment)
        except ValueError:
            valid = False
        if not valid:
            raise web.HTTPForbidden(text=json.dumps({"error": "请求来源校验失败，请从本应用页面操作"}),
                                   content_type="application/json")

    def require_mutation(self, request: web.Request) -> Session:
        self.require_origin(request)
        session = self.require_session(request)
        if not hmac.compare_digest(request.headers.get("X-CSRF-Token", "").encode("utf-8"),
                                   session.csrf.encode("ascii")):
            raise web.HTTPForbidden(text=json.dumps({"error": "页面凭证已失效，请刷新页面"}),
                                   content_type="application/json")
        return session

    @staticmethod
    def allowed_peer(request: web.Request) -> bool:
        # request.remote is the transport peer; forwarded headers are ignored.
        try:
            peer = ipaddress.ip_address((request.remote or "").split("%", 1)[0])
            if isinstance(peer, ipaddress.IPv6Address) and peer.ipv4_mapped:
                peer = peer.ipv4_mapped
            return any(peer.version == network.version and peer in network for network in ALLOWED_PEERS)
        except ValueError:
            return False

    async def supervisor(self, action: str, *, timeout: float = 30, **arguments) -> dict:
        writer = None

        async def exchange():
            nonlocal writer
            reader, writer = await asyncio.open_unix_connection(str(self.state / "control.sock"),
                                                               limit=MAX_CONTROL_REPLY + 1)
            message = {"action": action, **arguments}
            writer.write(json.dumps(message, ensure_ascii=False).encode("utf-8") + b"\n")
            await writer.drain()
            line = await reader.readline()
            if not line or len(line) > MAX_CONTROL_REPLY:
                raise SupervisorError("管理服务返回了无效响应")
            result = json.loads(line)
            if not isinstance(result, dict):
                raise SupervisorError("管理服务返回了无效响应")
            if result.get("ok") is False or result.get("error"):
                raise SupervisorError(str(result.get("error") or result.get("message") or "操作未完成"))
            return result

        try:
            return await asyncio.wait_for(exchange(), timeout)
        except SupervisorError:
            raise
        except asyncio.TimeoutError as exc:
            raise SupervisorError("操作仍未返回，请查看当前状态后重试") from exc
        except (OSError, ValueError, AttributeError) as exc:
            raise SupervisorError("管理服务暂时不可用，请稍后重试") from exc
        finally:
            if writer is not None:
                writer.close()
                with suppress(OSError, ConnectionError):
                    await writer.wait_closed()

    async def login(self, request: web.Request) -> web.Response:
        self.require_origin(request)
        await self.sync_credentials()
        peer = request.remote or "unknown"
        now = time.monotonic()
        # Bound dictionary growth even when untrusted peers rotate addresses.
        if len(self.attempts) >= 2048:
            self.attempts = defaultdict(deque, {k: v for k, v in self.attempts.items()
                                               if v and v[-1] > now - 300})
            if peer not in self.attempts and len(self.attempts) >= 2048:
                return web.json_response({"error": "登录请求较多，请稍后重试"}, status=429,
                                         headers={"Retry-After": "30"})
        attempts = self.attempts[peer]
        while attempts and attempts[0] <= now - 300:
            attempts.popleft()
        if len(attempts) >= 10:
            return web.json_response({"error": "尝试次数较多，请五分钟后重试"}, status=429,
                                     headers={"Retry-After": "300"})
        attempts.append(now)
        if request.content_length is not None and request.content_length > 4096:
            return web.json_response({"error": "登录信息过长"}, status=400)
        try:
            body = await request.json()
            password = body.get("password") if isinstance(body, dict) else None
            if not isinstance(password, str) or not 1 <= len(password.encode("utf-8")) <= 2048:
                raise ValueError("Invalid password shape")
        except (ValueError, UnicodeError, json.JSONDecodeError):
            return web.json_response({"error": "请输入访问密码"}, status=400)
        if self.hash_slots.locked():
            return web.json_response({"error": "正在处理其他登录，请稍后重试"}, status=429,
                                     headers={"Retry-After": "2"})
        revision = self.auth_revision
        async with self.hash_slots:
            candidate = await asyncio.to_thread(hashlib.scrypt, password.encode("utf-8"),
                                                 salt=self.salt, n=16384, r=8, p=1, dklen=32)
        await self.sync_credentials()
        if self.auth_revision != revision:
            return web.json_response({"error": "访问密码已变更，请重新登录"}, status=401)
        if not hmac.compare_digest(candidate, self.password_hash):
            return web.json_response({"error": "访问密码不正确"}, status=401)
        previous = request.cookies.get(self.cookie_name, "")
        await self.drop_session(previous)
        # A slow VNC close yields to password resets and credential refreshes.
        # Verify again after that last external wait. From this revision/hash
        # check through session publication there must be no further await.
        await self.sync_credentials()
        if self.auth_revision != revision or not hmac.compare_digest(candidate, self.password_hash):
            return web.json_response({"error": "访问密码已变更，请重新登录"}, status=401)
        self.attempts.pop(peer, None)
        if len(self.sessions) >= 64:
            return web.json_response({"error": "登录会话较多，请关闭不用的页面后再试"}, status=429)
        token = secrets.token_urlsafe(32)
        session = Session(csrf=secrets.token_urlsafe(32), expires=now + SESSION_SECONDS)
        self.sessions[token] = session
        response = web.json_response({"authenticated": True, "csrf": session.csrf,
                                      "app": self.app_id, "title": self.title})
        response.set_cookie(self.cookie_name, token, max_age=SESSION_SECONDS, httponly=True,
                            secure=True, samesite="Strict", path="/")
        return response

    async def drop_session(self, token: str) -> None:
        session = self.sessions.pop(token, None)
        if session:
            for socket in list(session.sockets):
                with suppress(OSError, ConnectionError, RuntimeError, asyncio.TimeoutError):
                    await asyncio.wait_for(socket.close(code=1008, message=b"Session ended"), timeout=2)

    async def change_password(self, request: web.Request) -> web.Response:
        self.require_mutation(request)
        if request.content_length is not None and request.content_length > 4096:
            return web.json_response({"error": "密码请求过长"}, status=400)
        try:
            raw = bytearray()
            async for chunk in request.content.iter_chunked(1024):
                raw.extend(chunk)
                if len(raw) > 4096:
                    raise CredentialError("密码请求过长")
            body = json.loads(raw)
            if not isinstance(body, dict) or set(body) != {"current_password", "new_password", "confirm_password"}:
                raise CredentialError("请填写当前密码、新密码及确认密码")
            current = validate_current_password(body["current_password"])
            new_password = validate_new_password(body["new_password"])
            if new_password != body["confirm_password"]:
                raise CredentialError("两次输入的新密码不一致")
        except (CredentialError, ValueError, UnicodeError) as error:
            message = str(error) if isinstance(error, CredentialError) else "请填写当前密码、新密码及确认密码"
            return web.json_response({"error": message}, status=400)
        if self.password_lock.locked():
            return web.json_response({"error": "另一个密码操作正在进行，请稍后重试"}, status=409)
        async with self.password_lock:
            await self.sync_credentials()
            self.require_mutation(request)
            now = time.monotonic()
            while self.password_attempts and self.password_attempts[0] <= now - 300:
                self.password_attempts.popleft()
            if len(self.password_attempts) >= 5:
                return web.json_response({"error": "密码修改尝试较多，请五分钟后重试"}, status=429,
                                         headers={"Retry-After": "300"})
            self.password_attempts.append(now)
            previous = self.auth_revision
            try:
                result = await self.supervisor("change_password", timeout=30, current_password=current,
                                               new_password=new_password, expected_revision=previous)
            finally:
                # Even an interrupted response may have committed a reset.
                await self.sync_credentials()
            if result.get("ok") is not True or self.auth_revision == previous:
                raise SupervisorError("密码服务尚未确认修改，请重新核对登录状态")
            response = web.json_response({"ok": True, "reauthenticate": True})
            # Debian 12 ships aiohttp 3.8, whose del_cookie only accepts path
            # and domain. Expire with set_cookie to retain our security flags
            # across supported aiohttp versions.
            response.set_cookie(self.cookie_name, "", max_age=0,
                                expires="Thu, 01 Jan 1970 00:00:00 GMT", path="/",
                                secure=True, httponly=True, samesite="Strict")
            return response

    async def logout(self, request: web.Request) -> web.Response:
        self.require_mutation(request)
        await self.drop_session(request.cookies.get(self.cookie_name, ""))
        response = web.json_response({"ok": True})
        response.set_cookie(self.cookie_name, "", max_age=0,
                            expires="Thu, 01 Jan 1970 00:00:00 GMT", path="/",
                            secure=True, httponly=True, samesite="Strict")
        return response

    async def session_info(self, request: web.Request) -> web.Response:
        session = self.session(request)
        if session is None:
            return web.json_response({"authenticated": False, "app": self.app_id, "title": self.title}, status=401)
        return web.json_response({"authenticated": True, "app": self.app_id, "title": self.title,
                                  "csrf": session.csrf, "vnc_password": self.vnc_password})

    async def status(self, request: web.Request) -> web.Response:
        self.require_session(request)
        data = await self.supervisor("status", timeout=15)
        return web.json_response({key: value for key, value in data.items() if key in PUBLIC_STATUS})

    async def action(self, request: web.Request) -> web.Response:
        self.require_mutation(request)
        action = request.match_info["action"]
        if action not in ACTIONS:
            raise web.HTTPNotFound()
        arguments = {}
        if action == "import":
            try:
                body = await request.json()
                content, fmt = body.get("content"), body.get("format")
                if (not isinstance(content, str) or not content.strip()
                        or len(content.encode("utf-8")) > MAX_IMPORT_BYTES
                        or not isinstance(fmt, str)
                        or fmt not in ({"share-links", "vless"} if self.app_id == "v2rayn" else {"clash"})):
                    raise ValueError("Invalid import")
                arguments = {"content": content, "format": "share-links" if fmt == "vless" else fmt}
            except (ValueError, AttributeError, UnicodeError):
                return web.json_response({"error": "请选择导入格式并填写内容，最多 1 MiB"}, status=400)
        result = await self.supervisor(action, timeout=90 if action == "check_update" else 1200, **arguments)
        # Supervisor replies are fixed metadata, never a config dump or credentials.
        permitted = {"ok", "message", "current", "latest", "available", "version", "updating",
                     "last_update", "network_active", "network_owner", "count", "imported", "format", "job",
                     "network_available", "network_current", "network_latest", "network_phase",
                     "network_cleanup_verified", "network_needs_recovery", "network_error"}
        return web.json_response({key: value for key, value in result.items() if key in permitted})

    async def vnc(self, request: web.Request) -> web.StreamResponse:
        self.require_origin(request)
        session = self.require_session(request)
        if self.vnc_connections >= 8:
            return web.json_response({"error": "远程桌面连接较多，请关闭不用的页面"}, status=429)
        reader, writer = None, None
        try:
            reader, writer = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", self.vnc_port), 5)
        except (OSError, asyncio.TimeoutError):
            return web.json_response({"error": "图形桌面尚未就绪，请稍后重连或重启客户端"}, status=503)
        socket = web.WebSocketResponse(heartbeat=25, max_msg_size=4 * 1024 * 1024, compress=False,
                                       protocols=("binary",))
        self.vnc_connections += 1
        session.sockets.add(socket)
        try:
            if self.session(request) is not session:
                return web.json_response({"error": "登录已过期，请重新登录"}, status=401)
            await socket.prepare(request)
            # Reset/logout can remove the session while the WebSocket handshake
            # is pending, before its socket can be closed. Recheck after that
            # wait; no further await may precede starting the relay tasks.
            try:
                await self.sync_credentials()
            except CredentialError:
                current_session = False
            else:
                current_session = self.session(request) is session
            if not current_session:
                with suppress(OSError, ConnectionError, asyncio.TimeoutError):
                    await asyncio.wait_for(socket.close(code=1008, message=b"Session ended"), timeout=2)
                return socket

            async def tcp_to_web():
                while chunk := await reader.read(64 * 1024):
                    await socket.send_bytes(chunk)

            async def web_to_tcp():
                async for message in socket:
                    if message.type == WSMsgType.BINARY:
                        writer.write(message.data)
                        await writer.drain()
                    elif message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR}:
                        break
                    elif message.type == WSMsgType.TEXT:
                        await socket.close(code=1003, message=b"Binary frames required")
                        break

            tasks = [asyncio.create_task(tcp_to_web()), asyncio.create_task(web_to_tcp())]
            try:
                done, pending = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
                for task in done:
                    with suppress(OSError, ConnectionError, RuntimeError, asyncio.CancelledError):
                        task.result()
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
        except (OSError, ConnectionError):
            pass
        finally:
            session.sockets.discard(socket)
            self.vnc_connections -= 1
            writer.close()
            with suppress(OSError, ConnectionError):
                await writer.wait_closed()
            with suppress(OSError, ConnectionError, RuntimeError):
                await socket.close()
        return socket

    async def novnc_asset(self, request: web.Request) -> web.FileResponse:
        self.require_session(request)
        tail = request.match_info["tail"]
        root = NOVNC_ROOT.resolve()
        relative = Path(tail)
        if not relative.parts or relative.parts[0] not in {"core", "vendor"}:
            raise web.HTTPNotFound()
        candidate = (root / relative).resolve()
        if not candidate.is_relative_to(root) or not candidate.is_file():
            raise web.HTTPNotFound()
        return web.FileResponse(candidate)

    async def expire_sessions(self, app):
        async def sweep():
            while True:
                await asyncio.sleep(2)
                with suppress(CredentialError):
                    await self.sync_credentials()
                for token, session in list(self.sessions.items()):
                    if session.expires <= time.monotonic():
                        await self.drop_session(token)
        task = asyncio.create_task(sweep())
        yield
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        for token in list(self.sessions):
            await self.drop_session(token)


@web.middleware
async def errors_and_headers(request: web.Request, handler):
    try:
        if not Portal.allowed_peer(request):
            raise web.HTTPForbidden(text=json.dumps({"error": "仅允许局域网与 Tailscale 访问"}),
                                    content_type="application/json")
        if request.path.startswith("/api/") or request.path == "/vnc":
            await request.app["portal"].sync_credentials()
        response = await handler(request)
    except CredentialError:
        response = web.json_response({"error": "访问凭据暂不可用，请联系 NAS 管理员"}, status=503)
    except SupervisorError as exc:
        response = web.json_response({"error": str(exc)}, status=409)
    except web.HTTPException as exc:
        response = exc
    if not isinstance(response, web.WebSocketResponse):
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; font-src 'self'; connect-src 'self'; "
            "worker-src 'self' blob:; base-uri 'none'; form-action 'self'; frame-ancestors 'self'"
        )
    return response


def create_app(state: Path, title: str, vnc_port: int) -> web.Application:
    portal = Portal(state, title, vnc_port)
    app = web.Application(middlewares=[errors_and_headers], client_max_size=8 * 1024 * 1024)
    app["portal"] = portal
    app.cleanup_ctx.append(portal.expire_sessions)

    async def index(request):
        return web.FileResponse(WEB_ROOT / "index.html")

    async def asset(request):
        name = request.match_info["name"]
        icons = {"icon-64.png": "icon_64.png", "icon-256.png": "icon_256.png"}
        if name in icons:
            path = ICON_ROOT / icons[name]
            if path.is_symlink() or not path.is_file():
                raise web.HTTPNotFound()
            return web.FileResponse(path)
        if name not in {"app.css", "app.js"}:
            raise web.HTTPNotFound()
        return web.FileResponse(WEB_ROOT / name)

    async def help_page(request):
        return web.FileResponse(WEB_ROOT / "help.html")

    app.router.add_get("/", index)
    app.router.add_get("/assets/{name}", asset)
    app.router.add_get("/help", help_page)
    app.router.add_post("/api/login", portal.login)
    app.router.add_post("/api/logout", portal.logout)
    app.router.add_get("/api/session", portal.session_info)
    app.router.add_get("/api/status", portal.status)
    app.router.add_post("/api/password", portal.change_password)
    app.router.add_post("/api/{action}", portal.action)
    app.router.add_get("/vnc", portal.vnc)
    app.router.add_get("/novnc/{tail:.*}", portal.novnc_asset)
    return app


def main():
    parser = argparse.ArgumentParser(description="fnOS native proxy desktop HTTPS entry")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--port", type=int, required=True)
    parser.add_argument("--title", default="NAS 原生代理")
    parser.add_argument("--vnc-port", type=int, required=True)
    args = parser.parse_args()
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(args.state / "tls.crt", args.state / "tls.key")
    web.run_app(create_app(args.state, args.title, args.vnc_port), host="0.0.0.0", port=args.port,
                ssl_context=context, access_log=None, print=None)


if __name__ == "__main__":
    main()
