import os

from .runtime import AbstractRuntime


_runtime: AbstractRuntime | None = None


def get_runtime() -> AbstractRuntime:
    global _runtime
    if _runtime is not None:
        return _runtime

    runtime_backend = os.getenv("STRIX_RUNTIME_BACKEND", "docker")

    if runtime_backend == "docker":
        from .docker_runtime import DockerRuntime

        _runtime = DockerRuntime()
        return _runtime

    raise ValueError(
        f"Unsupported runtime backend: {runtime_backend}. Only 'docker' is supported for now."
    )


__all__ = ["AbstractRuntime", "get_runtime"]
