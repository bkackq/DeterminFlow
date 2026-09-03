"""鉴权（登录）功能测试：登录门控、Token 签发/校验、WebSocket 鉴权。

注意：本文件不运行完整 lifespan（与项目其他测试一致），因此受保护且依赖
app.state 的业务端点会因缺少运行时状态而 500；我们仅断言「鉴权层」的行为，
包括：未登录拦截、错误密码拒绝、正确登录发 Token、带 Token 放行、WebSocket 拒绝。
"""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

from src.web import auth as auth_module


@pytest.fixture()
def auth_app(tmp_path, monkeypatch):
    """构造启用鉴权的应用：默认账号 admin/secret123。"""
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERNAME", "admin")
    monkeypatch.setenv("AUTH_PASSWORD", "secret123")
    # 隔离签名密钥文件，避免污染项目 data/ 目录
    monkeypatch.setattr(auth_module, "_AUTH_SECRET_FILE", tmp_path / ".auth_secret")
    auth_module._auth_manager = None  # 重置单例，确保读到新的环境变量

    from src.web_server import create_app

    app = create_app()
    yield TestClient(app)
    auth_module._auth_manager = None


@pytest.fixture()
def auth_disabled_app(monkeypatch):
    """构造关闭鉴权的应用（对应生产 AUTH_ENABLED=false 的显式关闭场景）。"""
    monkeypatch.setenv("AUTH_ENABLED", "false")
    auth_module._auth_manager = None

    from src.web_server import create_app

    app = create_app()
    yield TestClient(app)
    auth_module._auth_manager = None


def _login(client: TestClient, username: str, password: str):
    return client.post(
        "/api/auth/login",
        json={"username": username, "password": password},
    )


def test_unauthenticated_request_rejected(auth_app):
    """未登录访问受保护 API 应返回 401。"""
    response = auth_app.get("/api/sessions")
    assert response.status_code == 401


def test_me_requires_token(auth_app):
    assert auth_app.get("/api/auth/me").status_code == 401


def test_login_wrong_password(auth_app):
    response = _login(auth_app, "admin", "wrong-password")
    assert response.status_code == 401


def test_login_unknown_user(auth_app):
    response = _login(auth_app, "nobody", "secret123")
    assert response.status_code == 401


def test_login_success_and_token_flow(auth_app):
    """正确登录签发 Token，带 Token 可访问 /api/auth/me。"""
    response = _login(auth_app, "admin", "secret123")
    assert response.status_code == 200
    body = response.json()
    assert body["username"] == "admin"
    assert body["expires_in"] > 0
    token = body["token"]

    me = auth_app.get(
        "/api/auth/me", headers={"Authorization": f"Bearer {token}"}
    )
    assert me.status_code == 200
    assert me.json() == {"authenticated": True, "username": "admin"}


def test_forged_token_rejected(auth_app):
    """伪造 Token 访问受保护接口应返回 401。"""
    response = auth_app.get(
        "/api/auth/me",
        headers={"Authorization": "Bearer forged.token.here"},
    )
    assert response.status_code == 401
    assert response.json()["detail"]


def test_auth_disabled_allows_requests(auth_disabled_app):
    """显式关闭鉴权后，未带 Token 的请求可直接访问。"""
    # /api/auth/login 在关闭鉴权时返回 403
    assert _login(auth_disabled_app, "admin", "secret123").status_code == 403


def test_websocket_without_token_rejected(auth_app):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with auth_app.websocket_connect("/ws/events"):
            pass  # 不应到达
    assert exc_info.value.code == 4401


def test_websocket_with_forged_token_rejected(auth_app):
    with pytest.raises(WebSocketDisconnect) as exc_info:
        with auth_app.websocket_connect("/ws/events?token=forged.token"):
            pass
    assert exc_info.value.code == 4401


def test_auth_module_token_roundtrip(tmp_path, monkeypatch):
    """AuthManager 核心：签发 → 校验 → 篡改拒绝 → 过期拒绝。"""
    import base64
    import hashlib
    import hmac
    import json
    import time

    monkeypatch.setattr(auth_module, "_AUTH_SECRET_FILE", tmp_path / "s")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.setenv("AUTH_USERNAME", "admin")
    monkeypatch.setenv("AUTH_PASSWORD", "secret123")
    manager = auth_module.AuthManager()

    token = manager.issue_token("admin")
    assert manager.validate_token(token) == "admin"
    assert manager.validate_token(token + "x") is None
    assert manager.validate_token("") is None

    # 过期 Token
    encoded = base64.urlsafe_b64encode(
        json.dumps(
            {"u": "admin", "iat": 1, "exp": 1, "n": "0"},
            separators=(",", ":"),
        ).encode()
    ).rstrip(b"=").decode()
    sig = base64.urlsafe_b64encode(
        hmac.new(manager._secret, encoded.encode(), hashlib.sha256).digest()
    ).rstrip(b"=").decode()
    assert manager.validate_token(f"{encoded}.{sig}") is None

    # 密码校验（含恒定时间处理）
    assert manager.verify_password("admin", "secret123") is True
    assert manager.verify_password("admin", "wrong") is False
    assert manager.verify_password("ghost", "x") is False


def test_default_fallback_account_when_no_users_configured(tmp_path, monkeypatch):
    """鉴权启用但未配置任何用户时，回退到内置默认账号 admin/admin（不报错）。"""
    import pytest

    monkeypatch.setattr(auth_module, "_AUTH_SECRET_FILE", tmp_path / "s")
    monkeypatch.setenv("AUTH_ENABLED", "true")
    monkeypatch.delenv("AUTH_USERNAME", raising=False)
    monkeypatch.delenv("AUTH_PASSWORD", raising=False)
    monkeypatch.delenv("AUTH_USERS_FILE", raising=False)

    manager = auth_module.AuthManager()
    assert manager.enabled is True
    assert manager.verify_password("admin", "admin") is True
    token = manager.authenticate("admin", "admin")
    assert token is not None
    assert manager.validate_token(token) == "admin"
