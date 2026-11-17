"""HTTPS portal contract tests over a local HTTP fixture, with fake root IPC."""
import asyncio
import copy
from contextlib import suppress
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from aiohttp.test_utils import TestClient, TestServer

from runtime import credentials as C
from runtime import portal as P

ROOT = Path(__file__).resolve().parents[1]
OLD = "old"
NEW = "new-fixture-password-42"


def auth_config(password=OLD, app="v2rayn", revision=""):
    salt = hashlib.sha256((password + app + revision).encode()).digest()[:16]
    return {"app": app, "title": "v2rayN" if app == "v2rayn" else "Clash Verge Rev",
            "password_salt": salt.hex(), "password_hash": hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32).hex(),
            "vnc_password": "fixture8", "password_revision": revision}


def write_config(ui, value):
    path=ui/"portal.json";temporary=ui/"portal.new"
    temporary.write_bytes(json.dumps(value).encode());temporary.chmod(0o600);temporary.replace(path)


class PortalAuthTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        workspace=ROOT/"work/portal-auth-tests";workspace.mkdir(parents=True,exist_ok=True)
        temporary=tempfile.TemporaryDirectory(dir=workspace);self.addCleanup(temporary.cleanup)
        self.root=Path(temporary.name);self.ui=self.root/"ui";self.ui.mkdir(mode=0o700)
        write_config(self.ui,auth_config())
        self.app=P.create_app(self.ui,"v2rayN",5911);self.portal=self.app["portal"]
        self.client=TestClient(TestServer(self.app));await self.client.start_server();self.addAsyncCleanup(self.client.close)
        self.origin=str(self.client.make_url("/")).rstrip("/")
        self.calls=[]
        self.portal.supervisor=self.fake_supervisor

    async def fake_supervisor(self, action, **arguments):
        self.calls.append((action,arguments))
        if action=="change_password":
            value=C.read_portal_config(self.ui/"portal.json")
            if arguments["expected_revision"] != C.credential_revision(value):raise P.SupervisorError("访问密码已变更，请重新登录")
            if not C.verify_password(value,arguments["current_password"]):raise P.SupervisorError("当前访问密码不正确")
            write_config(self.ui,auth_config(arguments["new_password"],revision="rotated-fixture"))
            return {"ok":True,"reauthenticate":True}
        if action=="status":
            return {"network_active":True,"network_phase":"active","network_cleanup_verified":False,
                    "network_needs_recovery":False,"network_error":None,"password":"must never be returned"}
        return {"ok":True,"message":"fixture action accepted"}

    async def login(self, password=OLD, client=None, portal=None, origin=None):
        client=client or self.client;portal=portal or self.portal;origin=origin or self.origin
        response=await client.post("/api/login",json={"password":password},headers={"Origin":origin})
        data=await response.json()
        if response.status!=200:return response,data,None,None
        cookie=response.cookies[portal.cookie_name].value
        headers={"Cookie":portal.cookie_name+"="+cookie,"X-CSRF-Token":data["csrf"],"Origin":origin}
        return response,data,headers,cookie

    def password_body(self,**changes):
        return {"current_password":OLD,"new_password":NEW,"confirm_password":NEW,**changes}

    async def start_vnc_echo(self):
        """Exercise the real TCP/WebSocket relay without an installed desktop."""
        received=asyncio.Queue();closed=asyncio.Event();writers=set();handlers=set()

        async def echo(reader,writer):
            task=asyncio.current_task();handlers.add(task);writers.add(writer)
            try:
                while chunk:=await reader.read(64*1024):
                    received.put_nowait(chunk)
                    writer.write(chunk)
                    await writer.drain()
            except (OSError,ConnectionError):
                pass
            finally:
                writer.close()
                with suppress(OSError,ConnectionError):await writer.wait_closed()
                writers.discard(writer);handlers.discard(task);closed.set()

        server=await asyncio.start_server(echo,"127.0.0.1",0)
        self.portal.vnc_port=server.sockets[0].getsockname()[1]

        async def cleanup():
            server.close();await server.wait_closed()
            for writer in list(writers):writer.close()
            if handlers:await asyncio.wait_for(asyncio.gather(*list(handlers),return_exceptions=True),3)
        self.addAsyncCleanup(cleanup)
        return received,closed

    def assert_expired_cookie(self,response):
        cookie=response.cookies[self.portal.cookie_name]
        self.assertEqual(cookie.value,"")
        self.assertEqual(cookie["max-age"],"0")
        self.assertEqual(cookie["expires"],"Thu, 01 Jan 1970 00:00:00 GMT")
        self.assertEqual(cookie["path"],"/")
        self.assertEqual(cookie["samesite"],"Strict")
        self.assertTrue(cookie["secure"])
        self.assertTrue(cookie["httponly"])

    async def test_unauthenticated_password_change_cannot_reach_root(self):
        response=await self.client.post("/api/password",json=self.password_body(),headers={"Origin":self.origin})
        self.assertEqual(response.status,401);self.assertEqual(self.calls,[])

    async def test_password_change_rejects_cross_origin_and_missing_csrf(self):
        _,_,headers,_=await self.login()
        for changed in ({**headers,"Origin":"https://outside.invalid"},{**headers,"X-CSRF-Token":""}):
            response=await self.client.post("/api/password",json=self.password_body(),headers=changed)
            self.assertEqual(response.status,403)
        self.assertEqual(self.calls,[])

    async def test_password_request_validation_does_not_echo_credentials(self):
        _,_,headers,_=await self.login()
        cases=[self.password_body(new_password="short"),self.password_body(confirm_password="mismatched-fixture-value"),
               self.password_body(new_password="new-password\n",confirm_password="new-password\n"),
               {"current_password":OLD},self.password_body(extra="unrecognized")]
        for body in cases:
            response=await self.client.post("/api/password",json=body,headers=headers)
            self.assertEqual(response.status,400)
            text=await response.text();self.assertNotIn(NEW,text);self.assertNotIn("mismatched-fixture-value",text)
        self.assertEqual(self.calls,[])

    async def test_wrong_current_password_keeps_session_and_files(self):
        _,_,headers,_=await self.login();original=(self.ui/"portal.json").read_bytes()
        response=await self.client.post("/api/password",json=self.password_body(current_password="wrong-fixture-input"),headers=headers)
        self.assertEqual(response.status,409);self.assertEqual((self.ui/"portal.json").read_bytes(),original)
        self.assertNotIn("wrong-fixture-input",await response.text())
        response=await self.client.get("/api/session",headers=headers);self.assertEqual(response.status,200)

    async def test_success_invalidates_all_this_app_sessions_and_vnc_and_persists(self):
        _,_,first,token1=await self.login();_,_,second,token2=await self.login()
        socket1=AsyncMock();socket2=AsyncMock()
        self.portal.sessions[token1].sockets.add(socket1);self.portal.sessions[token2].sockets.add(socket2)
        response=await self.client.post("/api/password",json=self.password_body(),headers=first)
        self.assertEqual(response.status,200);self.assertEqual(await response.json(),{"ok":True,"reauthenticate":True})
        self.assert_expired_cookie(response)
        self.assertEqual(self.portal.sessions,{})
        socket1.close.assert_awaited_once();socket2.close.assert_awaited_once()
        for headers in (first,second):
            denied=await self.client.get("/api/session",headers=headers);self.assertEqual(denied.status,401)
        old,_,_,_=await self.login();self.assertEqual(old.status,401)
        current,_,_,_=await self.login(NEW);self.assertEqual(current.status,200)
        restarted=P.Portal(self.ui,"v2rayN",5911)
        self.assertEqual(restarted.password_hash,bytes.fromhex(auth_config(NEW,revision="rotated-fixture")["password_hash"]))
        self.assertEqual(self.calls[0][0],"change_password")

    async def test_external_admin_reset_reloads_without_portal_restart(self):
        _,_,headers,token=await self.login();socket=AsyncMock();self.portal.sessions[token].sockets.add(socket)
        write_config(self.ui,auth_config(NEW,revision="admin-reset-fixture"))
        response=await self.client.get("/api/session",headers=headers)
        self.assertEqual(response.status,401);socket.close.assert_awaited_once()
        current,_,_,_=await self.login(NEW);self.assertEqual(current.status,200)

    async def test_logout_expires_cookie_and_revokes_only_current_session(self):
        _,_,headers,token=await self.login();_,_,other_headers,other_token=await self.login()
        socket=AsyncMock();self.portal.sessions[token].sockets.add(socket)
        original_del_cookie=P.web.Response.del_cookie
        def aiohttp38_del_cookie(response,name,*,domain=None,path="/"):
            return original_del_cookie(response,name,domain=domain,path=path)
        # NAS Debian 12 has the older signature. Keep this executable even
        # when the local development environment has a newer aiohttp.
        with patch.object(P.web.Response,"del_cookie",aiohttp38_del_cookie):
            response=await self.client.post("/api/logout",headers=headers)
        self.assertEqual(response.status,200);self.assertEqual(await response.json(),{"ok":True})
        self.assert_expired_cookie(response)
        self.assertNotIn(token,self.portal.sessions);self.assertIn(other_token,self.portal.sessions)
        socket.close.assert_awaited_once()
        response=await self.client.get("/api/session",headers=headers);self.assertEqual(response.status,401)
        response=await self.client.get("/api/session",headers=other_headers);self.assertEqual(response.status,200)

    async def test_logout_rejects_cross_origin_and_missing_csrf(self):
        _,_,headers,token=await self.login()
        for changed in ({**headers,"Origin":"https://outside.invalid"},{**headers,"X-CSRF-Token":""}):
            response=await self.client.post("/api/logout",headers=changed)
            self.assertEqual(response.status,403);self.assertIn(token,self.portal.sessions)
            self.assertNotIn(self.portal.cookie_name,response.cookies)

    async def test_admin_reset_during_real_vnc_handshake_blocks_old_session_relay(self):
        received,closed=await self.start_vnc_echo()
        _,_,headers,token=await self.login()
        entered=asyncio.Event();release=asyncio.Event()
        original_prepare=P.web.WebSocketResponse.prepare

        async def delayed_prepare(socket,request):
            if request.path=="/vnc" and not socket.prepared:
                entered.set()
                await release.wait()
            return await original_prepare(socket,request)

        async def connect():
            return await self.client.ws_connect("/vnc",headers=headers,protocols=("binary",))

        with patch.object(P.web.WebSocketResponse,"prepare",delayed_prepare):
            pending=asyncio.create_task(connect())
            try:
                await asyncio.wait_for(entered.wait(),3)
                self.assertEqual(len(self.portal.sessions[token].sockets),1)
                write_config(self.ui,auth_config(NEW,revision="reset-during-vnc-handshake"))
                await self.portal.sync_credentials()
                self.assertEqual(self.portal.sessions,{})
                release.set()
                socket=await asyncio.wait_for(pending,3)
                try:
                    with suppress(ConnectionError,RuntimeError):
                        await socket.send_bytes(b"old-session-must-not-reach-desktop")
                    message=await asyncio.wait_for(socket.receive(),3)
                    self.assertIn(message.type,{P.WSMsgType.CLOSE,P.WSMsgType.CLOSED})
                    self.assertTrue(socket.closed)
                    await asyncio.wait_for(closed.wait(),3)
                    self.assertTrue(received.empty())
                    self.assertEqual(self.portal.vnc_connections,0)
                finally:
                    await socket.close()
            finally:
                release.set()
                if not pending.done():pending.cancel()
                await asyncio.gather(pending,return_exceptions=True)

    async def exercise_real_vnc_revocation(self,administrator=False):
        received,closed=await self.start_vnc_echo()
        _,_,headers,_=await self.login()
        socket=await self.client.ws_connect("/vnc",headers=headers,protocols=("binary",))
        try:
            await socket.send_bytes(b"authenticated-desktop-fixture")
            message=await asyncio.wait_for(socket.receive(),3)
            self.assertEqual(message.type,P.WSMsgType.BINARY)
            self.assertEqual(message.data,b"authenticated-desktop-fixture")
            self.assertEqual(await asyncio.wait_for(received.get(),3),message.data)
            pending=asyncio.create_task(socket.receive())
            try:
                if administrator:
                    write_config(self.ui,auth_config(NEW,revision="live-vnc-admin-reset"))
                    await self.portal.sync_credentials()
                else:
                    response=await self.client.post("/api/password",json=self.password_body(),headers=headers)
                    self.assertEqual(response.status,200)
                    self.assert_expired_cookie(response)
                message=await asyncio.wait_for(pending,3)
                self.assertIn(message.type,{P.WSMsgType.CLOSE,P.WSMsgType.CLOSED})
                self.assertTrue(socket.closed)
                self.assertEqual(self.portal.sessions,{})
                await asyncio.wait_for(closed.wait(),3)
                self.assertEqual(self.portal.vnc_connections,0)
                self.assertTrue(received.empty())
                response=await self.client.get("/api/session",headers=headers);self.assertEqual(response.status,401)
            finally:
                if not pending.done():pending.cancel()
                await asyncio.gather(pending,return_exceptions=True)
        finally:
            await socket.close()

    async def test_password_change_closes_real_vnc_connection(self):
        await self.exercise_real_vnc_revocation()

    async def test_admin_reset_closes_real_vnc_connection(self):
        await self.exercise_real_vnc_revocation(administrator=True)

    async def test_admin_reset_while_login_closes_old_vnc_cannot_mint_stale_session(self):
        _,_,headers,token=await self.login()
        closing=asyncio.Event();release=asyncio.Event()
        socket=AsyncMock()
        async def delayed_close(**_kwargs):
            closing.set()
            await release.wait()
        socket.close.side_effect=delayed_close
        self.portal.sessions[token].sockets.add(socket)

        async def another_old_password_login():
            return await self.client.post("/api/login",json={"password":OLD},headers=headers)
        pending=asyncio.create_task(another_old_password_login())
        try:
            await asyncio.wait_for(closing.wait(),2)
            # Simulate the root CLI committing a reset while the login handler
            # awaits a slow VNC close after it has verified the old password.
            write_config(self.ui,auth_config(NEW,revision="reset-during-vnc-close"))
            await self.portal.sync_credentials()
            release.set()
            response=await asyncio.wait_for(pending,3)
            self.assertEqual(response.status,401)
            self.assertNotIn(self.portal.cookie_name,response.cookies)
            self.assertEqual(self.portal.sessions,{})
        finally:
            release.set()
            if not pending.done():pending.cancel()
            await asyncio.gather(pending,return_exceptions=True)
        current,_,_,_=await self.login(NEW);self.assertEqual(current.status,200)

    async def test_two_apps_remain_isolated_after_one_password_change(self):
        other_ui=self.root/"clash-ui";other_ui.mkdir(mode=0o700);write_config(other_ui,auth_config(app="clash"))
        other_app=P.create_app(other_ui,"Clash Verge Rev",5912);other=other_app["portal"]
        client=TestClient(TestServer(other_app));await client.start_server();self.addAsyncCleanup(client.close)
        origin=str(client.make_url("/")).rstrip("/")
        _,_,other_headers,_=await self.login(client=client,portal=other,origin=origin)
        _,_,headers,_=await self.login()
        response=await self.client.post("/api/password",json=self.password_body(),headers=headers);self.assertEqual(response.status,200)
        response=await client.get("/api/session",headers=other_headers);self.assertEqual(response.status,200)
        response=await client.get("/api/session",headers=headers);self.assertEqual(response.status,401)
        self.assertEqual(C.read_portal_config(other_ui/"portal.json")["password_revision"],"")

    async def test_concurrent_root_reset_is_detected_and_old_session_is_revoked(self):
        _,_,headers,_=await self.login()
        async def reset_in_parallel(*_args,**_kwargs):
            write_config(self.ui,auth_config("administrator-fixture-password",revision="external"))
            raise P.SupervisorError("访问密码已变更，请重新登录")
        self.portal.supervisor=reset_in_parallel
        response=await self.client.post("/api/password",json=self.password_body(),headers=headers)
        self.assertEqual(response.status,409);self.assertEqual(self.portal.sessions,{})

    async def test_backend_must_confirm_persisted_change_before_success(self):
        _,_,headers,_=await self.login();self.portal.supervisor=AsyncMock(return_value={"ok":True,"reauthenticate":True})
        response=await self.client.post("/api/password",json=self.password_body(),headers=headers)
        self.assertEqual(response.status,409);self.assertNotIn(NEW,await response.text())

    async def test_password_change_is_rate_limited(self):
        _,_,headers,_=await self.login()
        for _ in range(5):
            response=await self.client.post("/api/password",json=self.password_body(current_password="wrong"),headers=headers)
            self.assertEqual(response.status,409)
        response=await self.client.post("/api/password",json=self.password_body(current_password="wrong"),headers=headers)
        self.assertEqual(response.status,429);self.assertEqual(len(self.calls),5)

    async def test_generic_action_cannot_bypass_password_endpoint(self):
        _,_,headers,_=await self.login()
        response=await self.client.post("/api/change_password",json=self.password_body(),headers=headers)
        self.assertEqual(response.status,404);self.assertEqual(self.calls,[])

    async def test_v2rayn_import_accepts_generic_and_legacy_share_name_only(self):
        _,_,headers,_=await self.login()
        for fmt in ("share-links","vless"):
            response=await self.client.post("/api/import",json={"format":fmt,"content":"vmess://disposable-fixture"},headers=headers)
            self.assertEqual(response.status,200);self.assertEqual(self.calls[-1][1]["format"],"share-links")
        response=await self.client.post("/api/import",json={"format":"clash","content":"proxies: []"},headers=headers)
        self.assertEqual(response.status,400)

    async def test_clash_import_only_exposes_yaml_capability(self):
        other_ui=self.root/"clash-ui";other_ui.mkdir(mode=0o700);write_config(other_ui,auth_config(app="clash"))
        other_app=P.create_app(other_ui,"Clash Verge Rev",5912);other=other_app["portal"];other.supervisor=AsyncMock(return_value={"ok":True})
        client=TestClient(TestServer(other_app));await client.start_server();self.addAsyncCleanup(client.close)
        origin=str(client.make_url("/")).rstrip("/");_,_,headers,_=await self.login(client=client,portal=other,origin=origin)
        response=await client.post("/api/import",json={"format":"share-links","content":"vmess://disposable-fixture"},headers=headers)
        self.assertEqual(response.status,400);other.supervisor.assert_not_awaited()
        response=await client.post("/api/import",json={"format":"clash","content":"proxies: []"},headers=headers)
        self.assertEqual(response.status,200)

    async def test_status_preserves_network_state_fields_but_never_secret_fields(self):
        _,_,headers,_=await self.login();response=await self.client.get("/api/status",headers=headers)
        data=await response.json();self.assertEqual(data["network_phase"],"active")
        self.assertIn("network_needs_recovery",data);self.assertNotIn("password",data)

    async def test_public_icons_and_help_are_fixed_assets_not_private_state(self):
        icons=self.root/"icons";icons.mkdir();(icons/"icon_64.png").write_bytes(b"fixture-icon64");(icons/"icon_256.png").write_bytes(b"fixture-icon256")
        web=self.root/"web";web.mkdir();(web/"help.html").write_text("<h1>本机使用说明</h1>",encoding="utf-8")
        with patch.object(P,"ICON_ROOT",icons),patch.object(P,"WEB_ROOT",web):
            for name,expected in (("icon-64.png",b"fixture-icon64"),("icon-256.png",b"fixture-icon256")):
                response=await self.client.get("/assets/"+name);self.assertEqual(response.status,200);self.assertEqual(await response.read(),expected)
                self.assertEqual(response.headers["Content-Type"],"image/png")
            response=await self.client.get("/help");self.assertEqual(response.status,200)
            self.assertIn("本机使用说明",await response.text())
            for path in ("/assets/portal.json","/assets/access.txt","/assets/tls.key"):
                response=await self.client.get(path);self.assertEqual(response.status,404)

    async def test_invalid_changed_auth_state_fails_closed_and_revokes_sessions(self):
        _,_,headers,_=await self.login();(self.ui/"portal.json").write_text("invalid fixture state")
        response=await self.client.get("/api/session",headers=headers)
        self.assertEqual(response.status,503);self.assertEqual(self.portal.sessions,{})
        self.assertNotIn("invalid fixture state",await response.text())


if __name__=="__main__":unittest.main()
