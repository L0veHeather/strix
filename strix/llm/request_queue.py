import asyncio
import logging
import os
import threading
import time
from typing import Any

import litellm
from litellm import ModelResponse, completion
from tenacity import retry, retry_if_exception, stop_after_attempt, wait_exponential


logger = logging.getLogger(__name__)


def should_retry_exception(exception: Exception) -> bool:
    status_code = None

    if hasattr(exception, "status_code"):
        status_code = exception.status_code
    elif hasattr(exception, "response") and hasattr(exception.response, "status_code"):
        status_code = exception.response.status_code

    if status_code is not None:
        return bool(litellm._should_retry(status_code))
    return True


RETRY_ATTEMPTS = int(os.getenv("LLM_RETRY_ATTEMPTS", "4"))
RETRY_MULTIPLIER = float(os.getenv("LLM_RETRY_MULTIPLIER", "2"))
RETRY_MIN_SECONDS = float(os.getenv("LLM_RETRY_MIN_SECONDS", "4"))
RETRY_MAX_SECONDS = float(os.getenv("LLM_RETRY_MAX_SECONDS", "60"))


class LLMRequestQueue:
    def __init__(self, max_concurrent: int = 6, delay_between_requests: float = 5.0):
        rate_limit_delay = os.getenv("LLM_RATE_LIMIT_DELAY")
        if rate_limit_delay:
            delay_between_requests = float(rate_limit_delay)

        rate_limit_concurrent = os.getenv("LLM_RATE_LIMIT_CONCURRENT")
        if rate_limit_concurrent:
            max_concurrent = int(rate_limit_concurrent)

        self.max_concurrent = max_concurrent
        self.delay_between_requests = delay_between_requests
        self._semaphore = threading.BoundedSemaphore(max_concurrent)
        self._last_request_time = 0.0
        self._lock = threading.Lock()

    async def make_request(self, completion_args: dict[str, Any]) -> ModelResponse:
        try:
            while not self._semaphore.acquire(timeout=0.2):
                await asyncio.sleep(0.1)

            # Reserve the next available request slot based on the prior request end.
            # Using the future timestamp (old behavior) caused the delay to compound
            # across concurrent callers, stretching gaps well beyond the intended
            # rate limit and making the system appear stuck.
            with self._lock:
                now = time.time()
                next_allowed = max(self._last_request_time + self.delay_between_requests, now)
                sleep_needed = max(0.0, next_allowed - now)
                self._last_request_time = next_allowed

            if sleep_needed > 0:
                await asyncio.sleep(sleep_needed)

            return await self._reliable_request(completion_args)
        finally:
            self._semaphore.release()

    @retry(  # type: ignore[misc]
        stop=stop_after_attempt(RETRY_ATTEMPTS),
        wait=wait_exponential(
            multiplier=RETRY_MULTIPLIER,
            min=RETRY_MIN_SECONDS,
            max=RETRY_MAX_SECONDS,
        ),
        retry=retry_if_exception(should_retry_exception),
        reraise=True,
    )
    async def _reliable_request(self, completion_args: dict[str, Any]) -> ModelResponse:
        response = completion(**completion_args, stream=False)
        if isinstance(response, ModelResponse):
            return response
        self._raise_unexpected_response()
        raise RuntimeError("Unreachable code")

    def _raise_unexpected_response(self) -> None:
        raise RuntimeError("Unexpected response type")


_global_queue: LLMRequestQueue | None = None


def get_global_queue() -> LLMRequestQueue:
    global _global_queue  # noqa: PLW0603
    if _global_queue is None:
        _global_queue = LLMRequestQueue()
    return _global_queue
