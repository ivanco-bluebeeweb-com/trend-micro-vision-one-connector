"""Trend Micro Vision One Connector entrypoint."""
from __future__ import annotations

import handlers_connection  # noqa: F401
import handlers_workbench  # noqa: F401
import handlers_endpoints  # noqa: F401
import handlers_suspicious_objects  # noqa: F401
import handlers_oat  # noqa: F401
import handlers_search  # noqa: F401
import handlers_audit  # noqa: F401
import panels  # noqa: F401
import panels_center  # noqa: F401
import panels_settings  # noqa: F401
from app import ext

extension = ext
