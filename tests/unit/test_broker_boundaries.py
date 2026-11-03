# SPDX-FileCopyrightText: 2026 Jiri Vyskocil
# SPDX-License-Identifier: Apache-2.0

"""A container's credential namespace remains authoritative throughout each connection."""

from __future__ import annotations

import asyncio
import json
from contextlib import closing
from dataclasses import asdict

import pytest
from aiohttp import ClientError, WSMsgType, web
from aiohttp.test_utils import TestClient, TestServer

from terok_sandbox import BrokerContext
from terok_sandbox.vault.daemon import PHANTOM_CREDENTIALS_MARKER
from terok_sandbox.vault.daemon.token_broker import UnixBind, VaultProxy, _build_app, _TokenDB
from terok_sandbox.vault.store.db import CredentialDB

_CONTEXT = BrokerContext("project", "task", "project")
_PROVIDER = "anthropic"
_TIMEOUT = 3


@pytest.mark.parametrize(
    "context", [None, {"scope": "project", "subject": "task", "credential_set": "default"}]
)
def test_broker_entry_points_reject_untrusted_context_before_opening_vault(tmp_path, context):
    """Neither a missing identity nor a plain mapping can bypass the canonical context type."""
    db_path = tmp_path / "unopened.db"
    db_path_text, routes_path = str(db_path), str(tmp_path / "routes.json")
    bind = UnixBind(tmp_path / "vault.sock")
    with pytest.raises(ValueError, match="Missing broker context"):
        _build_app(db_path_text, routes_path, broker_context=context)
    with pytest.raises(ValueError, match="Missing broker context"):
        VaultProxy(db_path=db_path, broker_context=context, bind=bind)
    assert not db_path.exists()


@pytest.mark.parametrize("field", ["scope", "subject", "credential_set"])
@pytest.mark.parametrize("value", ["", " ", None, 42])
def test_context_rejects_missing_identity(field, value):
    """No empty/default inference can silently broaden broker authority."""
    identity = {**asdict(_CONTEXT), field: value}
    with pytest.raises(ValueError):
        BrokerContext(**identity)


@pytest.mark.parametrize("field", ["scope", "subject", "credential_set"])
def test_foreign_token_cannot_select_namespace(tmp_path, field):
    """Even a real live token cannot replace this container's trusted identity."""
    path = tmp_path / "vault.db"
    with closing(CredentialDB(path, passphrase="test")) as db:
        foreign = {**asdict(_CONTEXT), field: "foreign"}
        token = db.create_token(**foreign, provider=_PROVIDER)
        assert _TokenDB(str(path), passphrase="test").authorize(token, _CONTEXT) is None


def test_marker_requires_exact_live_provider_grant(tmp_path):
    """A marker is a provider selector, never an authorization fallback."""
    path = tmp_path / "vault.db"
    with closing(CredentialDB(path, passphrase="test")) as db:
        broker = _TokenDB(str(path), passphrase="test")
        assert broker.authorize(PHANTOM_CREDENTIALS_MARKER, _CONTEXT) is None
        db.create_token("project", "different-task", "project", _PROVIDER)
        db.create_token("project", "task", "default", _PROVIDER)
        db.create_token("project", "task", "project", "other-provider")
        assert broker.authorize(PHANTOM_CREDENTIALS_MARKER, _CONTEXT) is None
        token = db.create_token(**asdict(_CONTEXT), provider=_PROVIDER)
        assert broker.authorize(PHANTOM_CREDENTIALS_MARKER, _CONTEXT) == {
            **asdict(_CONTEXT),
            "provider": _PROVIDER,
        }
        assert broker.authorize(token, _CONTEXT) is not None
        db.revoke_tokens(_CONTEXT.scope, _CONTEXT.subject)
        assert broker.authorize(PHANTOM_CREDENTIALS_MARKER, _CONTEXT) is None
        assert broker.authorize(token, _CONTEXT) is None
        assert broker.authorize("unknown", _CONTEXT) is None


def _app(tmp_path, upstream, context, kind):
    """Seed two visibly different sets and return a scoped broker plus its live grant."""
    path = tmp_path / "vault.db"
    with closing(CredentialDB(path, passphrase="test")) as db:
        for credential_set in ("default", "project"):
            value = f"{credential_set}-secret"
            data = {"type": "oauth", "access_token": value} if kind == "oauth" else {"key": value}
            db.store_credential(credential_set, _PROVIDER, data)
        token = db.create_token(**asdict(context), provider=_PROVIDER)
    routes = tmp_path / "routes.json"
    routes.write_text(
        json.dumps({_PROVIDER: {"upstream": str(upstream.make_url("/")), "auth_header": "dynamic"}})
    )
    return _build_app(str(path), str(routes), broker_context=context, passphrase="test"), token


@pytest.mark.needs_loopback
@pytest.mark.asyncio
@pytest.mark.parametrize("credential_set", ["default", "project"])
@pytest.mark.parametrize("kind", ["oauth", "api_key"])
@pytest.mark.parametrize("marker", [False, True])
async def test_oauth_and_api_keys_use_same_container_set(tmp_path, credential_set, kind, marker):
    """Both auth types and both token forms select exactly the launch-authorized set."""

    async def echo(request):
        return web.json_response(dict(request.headers))

    upstream_app = web.Application()
    upstream_app.router.add_get("/", echo)
    async with TestServer(upstream_app) as upstream:
        context = BrokerContext("project", "task", credential_set)
        app, token = _app(tmp_path, upstream, context, kind)
        async with TestClient(TestServer(app)) as client:
            token = PHANTOM_CREDENTIALS_MARKER if marker else token
            response = await client.get("/", headers={"Authorization": f"Bearer {token}"})
            assert response.status == 200
            headers = await response.json()
            header = "Authorization" if kind == "oauth" else "x-api-key"
            expected = (
                f"Bearer {credential_set}-secret" if kind == "oauth" else f"{credential_set}-secret"
            )
            assert headers[header] == expected


@pytest.mark.needs_loopback
@pytest.mark.asyncio
@pytest.mark.parametrize("marker", [False, True])
async def test_revocation_disconnects_established_http_stream(tmp_path, marker):
    """Revocation closes an already-open response, not only future requests."""
    release = asyncio.Event()

    async def stream(request):
        response = web.StreamResponse()
        await response.prepare(request)
        await response.write(b"ready")
        await release.wait()
        return response

    upstream_app = web.Application()
    upstream_app.router.add_get("/", stream)
    async with TestServer(upstream_app) as upstream:
        app, token = _app(tmp_path, upstream, _CONTEXT, "api_key")
        async with TestClient(TestServer(app)) as client:
            token = PHANTOM_CREDENTIALS_MARKER if marker else token
            response = await client.get("/", headers={"Authorization": f"Bearer {token}"})
            assert await response.content.readexactly(5) == b"ready"
            try:
                with closing(CredentialDB(tmp_path / "vault.db", passphrase="test")) as db:
                    db.revoke_tokens(_CONTEXT.scope, _CONTEXT.subject)
                remaining_response = response.read()
                with pytest.raises(ClientError):
                    await asyncio.wait_for(remaining_response, _TIMEOUT)
                denied = await client.get("/", headers={"Authorization": f"Bearer {token}"})
                assert denied.status == 401
            finally:
                release.set()


@pytest.mark.needs_loopback
@pytest.mark.asyncio
@pytest.mark.parametrize("marker", [False, True])
async def test_revocation_closes_both_websocket_legs(tmp_path, marker):
    """An idle websocket cannot keep its credentials alive after task revocation."""
    closed = asyncio.Event()

    async def websocket(request):
        ws = web.WebSocketResponse()
        await ws.prepare(request)
        try:
            async for message in ws:
                await ws.send_str(message.data)
        finally:
            closed.set()
        return ws

    upstream_app = web.Application()
    upstream_app.router.add_get("/", websocket)
    async with TestServer(upstream_app) as upstream:
        app, token = _app(tmp_path, upstream, _CONTEXT, "oauth")
        async with TestClient(TestServer(app)) as client:
            token = PHANTOM_CREDENTIALS_MARKER if marker else token
            ws = await client.ws_connect("/", headers={"Authorization": f"Bearer {token}"})
            await ws.send_str("ready")
            assert (await ws.receive()).data == "ready"
            with closing(CredentialDB(tmp_path / "vault.db", passphrase="test")) as db:
                db.revoke_tokens(_CONTEXT.scope, _CONTEXT.subject)
            message = await asyncio.wait_for(ws.receive(), _TIMEOUT)
            assert message.type in {WSMsgType.CLOSE, WSMsgType.CLOSED, WSMsgType.ERROR}
            await asyncio.wait_for(closed.wait(), _TIMEOUT)
            await ws.close()
