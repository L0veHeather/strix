"""Strix API Server.

FastAPI backend providing REST API and WebSocket for the desktop UI.
"""

from strix.server.app import app, create_app
from strix.server.routes import scans, plugins, results, websocket

__all__ = [
    "app",
    "create_app",
    "scans",
    "plugins",
    "results",
    "websocket",
]
