"""DeterminFlow 鉴权核心模块。

提供基于用户名/密码的登录校验与无状态签名 Token（HMAC-SHA256）。

设计要点：
- 无状态：Token 内嵌用户名与过期时间，服务端无需会话存储，支持多进程/多 worker。
- 签名密钥：优先读取环境变量 AUTH_SECRET；未设置时自动生成并持久化到
  DATA_DIR/.auth_secret（权限 600），保证重启后已签发 Token 依然有效。
- 用户来源（按优先级合并）：
    1. AUTH_USERS_FILE 指向的 JSON 文件（默认 DATA_DIR/auth_users.json），
       每项 {"username": ..., "password": ...} 或 {"username": ..., "password_hash": "<sha256 hex>"}
    2. 环境变量 AUTH_USERNAME / AUTH_PASSWORD（同名覆盖文件中的用户）
    3. 均未配置时使用内置默认用户 admin / admin（启动时打印醒目警告，要求尽快修改）
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
import os
import secrets
import time
from pathlib import Path

from src.config import DATA_DIR

logger = logging.getLogger(__name__)

_TOKEN_ALG = "HS256"
_DEFAULT_TTL_DAYS = 7
_DEFAULT_USERNAME = "admin"
_DEFAULT_PASSWORD = "admin"

_AUTH_SECRET_FILE = DATA_DIR / ".auth_secret"


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(data: str) -> bytes:
    pad = "=" * (-len(data) % 4)
    return base64.urlsafe_b64decode(data + pad)


def sha256_hex(value: str) -> str:
    """对明文密码做 SHA-256 十六进制哈希，用于 auth_users.json 中存储 password_hash。"""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _constant_time_eq(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _load_secret() -> bytes:
    """获取签名密钥：环境变量 AUTH_SECRET > 持久化文件 > 新生成并持久化。"""
    env_secret = os.getenv("AUTH_SECRET", "").strip()
    if env_secret:
        return env_secret.encode("utf-8")
    if _AUTH_SECRET_FILE.exists():
        try:
            raw = _AUTH_SECRET_FILE.read_text(encoding="utf-8").strip()
            if raw:
                return raw.encode("utf-8")
        except OSError:
            logger.warning("无法读取 %s，将重新生成签名密钥", _AUTH_SECRET_FILE)
    secret = secrets.token_urlsafe(48)
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        _AUTH_SECRET_FILE.write_text(secret, encoding="utf-8")
        try:
            _AUTH_SECRET_FILE.chmod(0o600)
        except OSError:
            pass
        logger.info("已生成新的鉴权签名密钥并持久化到 %s", _AUTH_SECRET_FILE)
    except OSError:
        logger.warning("无法持久化鉴权签名密钥到 %s，重启后 Token 将失效", _AUTH_SECRET_FILE)
    return secret.encode("utf-8")


class AuthManager:
    """用户校验 + 签名 Token 的签发与验证。"""

    def __init__(self) -> None:
        self._secret = _load_secret()
        self._enabled = self._resolve_enabled()
        self._ttl_seconds = self._resolve_ttl()
        self._users: dict[str, dict] = self._load_users()
        if self._enabled and not self._users:
            # 兜底：始终保证有一个可用账号，项目开箱即用。
            self._users[_DEFAULT_USERNAME] = {
                "password": _DEFAULT_PASSWORD,
                "is_default": True,
            }
            logger.warning(
                "鉴权已启用但未配置任何用户，已使用内置默认账号 %s/%s。"
                "请尽快通过 AUTH_USERNAME/AUTH_PASSWORD 环境变量或 %s 修改！",
                _DEFAULT_USERNAME, _DEFAULT_PASSWORD, self.users_file,
            )
        if self._enabled:
            logger.info(
                "鉴权已启用：可用用户 %s，Token 有效期 %d 天",
                ", ".join(sorted(self._users.keys())), self._ttl_seconds // 86400,
            )
        else:
            logger.info("鉴权未启用（AUTH_ENABLED=false 或未配置用户），所有请求直接放行")

    # ---------- 配置解析 ----------

    @property
    def users_file(self) -> Path:
        custom = os.getenv("AUTH_USERS_FILE", "").strip()
        if custom:
            return Path(custom).expanduser().resolve()
        return DATA_DIR / "auth_users.json"

    def _resolve_enabled(self) -> bool:
        raw = os.getenv("AUTH_ENABLED", "").strip().lower()
        if raw:
            return raw in ("1", "true", "yes", "on")
        # 默认启用鉴权：任何人访问都必须登录后才能使用项目。
        # 测试环境通过 AUTH_ENABLED=false 显式关闭（见 tests/conftest.py）。
        return True

    def _resolve_ttl(self) -> int:
        try:
            days = int(os.getenv("AUTH_TOKEN_TTL_DAYS", str(_DEFAULT_TTL_DAYS)))
        except ValueError:
            days = _DEFAULT_TTL_DAYS
        return max(1, days) * 86400

    # ---------- 用户加载 ----------

    def _load_users(self) -> dict[str, dict]:
        users: dict[str, dict] = {}
        # 1) JSON 用户文件
        if self.users_file.exists():
            try:
                raw = json.loads(self.users_file.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    raw = list(raw.values())
                for entry in raw:
                    if not isinstance(entry, dict):
                        continue
                    username = str(entry.get("username") or "").strip()
                    if not username:
                        continue
                    users[username] = dict(entry)
            except (OSError, json.JSONDecodeError) as e:
                logger.error("鉴权用户文件 %s 解析失败：%s", self.users_file, e)
        # 2) 环境变量单用户（覆盖同名）
        env_user = os.getenv("AUTH_USERNAME", "").strip()
        env_pass = os.getenv("AUTH_PASSWORD", "")
        if env_user:
            users[env_user] = {"password": env_pass}
        return users

    def _password_ok(self, record: dict, candidate: str) -> bool:
        stored_hash = record.get("password_hash")
        if isinstance(stored_hash, str) and stored_hash:
            return _constant_time_eq(sha256_hex(candidate), stored_hash.lower())
        stored_plain = record.get("password")
        if isinstance(stored_plain, str):
            return _constant_time_eq(stored_plain, candidate)
        return False

    # ---------- 对外能力 ----------

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def token_ttl_seconds(self) -> int:
        return self._ttl_seconds

    def usernames(self) -> list[str]:
        return sorted(self._users.keys())

    def verify_password(self, username: str, password: str) -> bool:
        if not self._enabled:
            return True
        record = self._users.get(username)
        if record is None:
            # 恒定时间比较，避免通过响应时间探测用户名是否存在
            _constant_time_eq(secrets.token_hex(8), secrets.token_hex(8))
            return False
        return self._password_ok(record, password)

    # ---------- Token ----------

    def issue_token(self, username: str) -> str:
        now = int(time.time())
        payload = {
            "u": username,
            "iat": now,
            "exp": now + self._ttl_seconds,
            "n": secrets.token_hex(8),
        }
        encoded = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
        sig = _b64url_encode(
            hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
        )
        return f"{encoded}.{sig}"

    def validate_token(self, token: str) -> str | None:
        """校验 Token，返回用户名；无效或过期返回 None。"""
        if not token:
            return None
        try:
            encoded, sig = token.split(".", 1)
            expected = _b64url_encode(
                hmac.new(self._secret, encoded.encode("ascii"), hashlib.sha256).digest()
            )
            if not _constant_time_eq(expected, sig):
                return None
            payload = json.loads(_b64url_decode(encoded).decode("utf-8"))
            exp = int(payload.get("exp", 0))
            if exp < int(time.time()):
                return None
            username = str(payload.get("u") or "")
            if not username or username not in self._users:
                return None
            return username
        except Exception:
            return None

    def authenticate(self, username: str, password: str) -> str | None:
        """校验用户名密码，成功返回 Token，失败返回 None。"""
        if not self._enabled:
            return None
        if self.verify_password(username, password):
            return self.issue_token(username)
        return None

    # ---------- 请求侧解析 ----------

    @staticmethod
    def extract_token_from_headers(headers: dict) -> str | None:
        """从请求头中解析 Bearer Token。headers 为 dict 或 Headers 对象。"""
        auth = headers.get("authorization") or headers.get("Authorization")
        if not auth:
            return None
        parts = str(auth).split(" ", 1)
        if len(parts) != 2 or parts[0].lower() != "bearer":
            return None
        return parts[1].strip() or None

    def require_http(self, headers: dict) -> str | None:
        """HTTP 中间件使用：解析并校验请求头中的 Token，返回用户名或 None。"""
        token = self.extract_token_from_headers(headers)
        if not token:
            return None
        return self.validate_token(token)

    def require_ws(self, headers: dict, query_params: dict) -> str | None:
        """WebSocket 握手鉴权：优先 Authorization 头，其次 ?token= 查询参数。"""
        token = self.extract_token_from_headers(headers)
        if not token:
            token = (query_params.get("token") or [None])
            if isinstance(token, list):
                token = token[0] if token else None
        if not token:
            return None
        return self.validate_token(str(token))


# 进程级单例：供中间件与 WebSocket 处理共用
_auth_manager: AuthManager | None = None


def get_auth_manager() -> AuthManager:
    global _auth_manager
    if _auth_manager is None:
        _auth_manager = AuthManager()
    return _auth_manager
