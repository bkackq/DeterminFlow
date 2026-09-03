"""鉴权 REST 路由：登录 / 登出 / 当前用户信息。"""
from __future__ import annotations

from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from src.web.auth import AuthManager, get_auth_manager

router = APIRouter(prefix="/api/auth", tags=["auth"])


class LoginRequest(BaseModel):
    username: str = Field(..., min_length=1, max_length=128)
    password: str = Field(..., min_length=1, max_length=256)


class LoginResponse(BaseModel):
    token: str
    username: str
    expires_in: int  # 秒


@router.post("/login", response_model=LoginResponse)
def login(body: LoginRequest) -> LoginResponse:
    """登录：校验用户名密码，成功返回签名 Token。"""
    auth: AuthManager = get_auth_manager()
    if not auth.enabled:
        raise HTTPException(status_code=403, detail="鉴权未启用")
    token = auth.authenticate(body.username, body.password)
    if not token:
        raise HTTPException(status_code=401, detail="用户名或密码错误")
    return LoginResponse(
        token=token,
        username=body.username,
        expires_in=auth.token_ttl_seconds,
    )


@router.post("/logout")
def logout() -> dict:
    """登出：Token 为无状态签名，服务端无需注销；客户端丢弃即可。"""
    return {"ok": True}


@router.get("/me")
def me(request: Request) -> dict:
    """当前用户信息。该接口本身也被鉴权中间件保护。"""
    username = getattr(request.state, "auth_username", None)
    if not username:
        raise HTTPException(status_code=401, detail="未认证")
    return {"authenticated": True, "username": username}


@router.get("/status")
def status(request: Request) -> dict:
    """鉴权状态（开放接口，无需登录）。

    返回鉴权是否启用；启用时附带当前 Token 是否有效。
    前端据此决定进入登录页还是直接进入主界面。
    """
    auth: AuthManager = get_auth_manager()
    if not auth.enabled:
        return {"enabled": False, "authenticated": True, "username": None}
    token = auth.extract_token_from_headers(request.headers)
    username = auth.validate_token(token) if token else None
    return {
        "enabled": True,
        "authenticated": username is not None,
        "username": username,
    }
