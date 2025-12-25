"""Runtime module - simplified without Docker dependency."""

from .runtime import AbstractRuntime


_runtime: AbstractRuntime | None = None


def get_runtime() -> AbstractRuntime:
    """Get the runtime instance. Currently returns a no-op runtime."""
    global _runtime
    if _runtime is not None:
        return _runtime
    
    # Return a simple no-op runtime since Docker is removed
    _runtime = NoOpRuntime()
    return _runtime


class NoOpRuntime(AbstractRuntime):
    """A no-op runtime that doesn't require Docker."""
    
    def __init__(self):
        pass
    
    async def start(self):
        pass
    
    async def stop(self):
        pass
    
    async def execute(self, command: str) -> str:
        return ""
    
    async def is_ready(self) -> bool:
        return True


__all__ = ["AbstractRuntime", "get_runtime", "NoOpRuntime"]
