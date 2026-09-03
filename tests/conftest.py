"""Test-process fallback for the community Executor Pool defaults.

Community runtime defaults are process mode with four members. Tests keep the
supported environment-variable rollback to inline/1 unless a case overrides it.
"""
from __future__ import annotations

import os

os.environ.setdefault("DETERMINFLOW_WORKFLOW_EXECUTOR_MODE", "inline")
os.environ.setdefault("DETERMINFLOW_WORKFLOW_EXECUTOR_COUNT", "1")
# 测试环境默认关闭鉴权（生产默认强制登录），保持既有测试对 API 的直接访问。
os.environ.setdefault("AUTH_ENABLED", "false")
