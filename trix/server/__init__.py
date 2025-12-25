"""Trix API Server.

FastAPI backend providing REST API and WebSocket for the desktop UI.
"""

from trix.server.app import app, create_app
from trix.server.routes import scans, plugins, results, websocket

__all__ = [
    "app",
    "create_app",
    "scans",
    "plugins",
    "results",
    "websocket",
]
