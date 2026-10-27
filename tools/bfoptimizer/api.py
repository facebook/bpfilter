# Copyright (c) Meta Platforms, Inc. and affiliates.
"""OpenRouter Chat Completions transport, using only the standard library."""

import asyncio
import concurrent.futures
import http.client
import json
import logging
import os
import threading
import urllib.error
import urllib.request

API_URL = "https://openrouter.ai/api/v1"

# Responses are not streamed: the body only arrives once the whole generation,
# reasoning included, is done.
REQUEST_TIMEOUT = 1800
MAX_RETRIES = 6

log = logging.getLogger("bfoptimizer")


class TransientError(RuntimeError):
    """Request failure that the same request may not hit again."""

    def __init__(self, message: str, retry_after: float = 0.0) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def api_key() -> str:
    key = os.environ.get("OPENROUTER_API_KEY", "").strip()
    if not key:
        raise RuntimeError("set OPENROUTER_API_KEY before running bfoptimizer")

    return key


def error_text(error: object) -> str:
    """Return the message of an OpenRouter error object."""

    if isinstance(error, dict) and error.get("message"):
        return str(error["message"])

    return str(error)


def _retryable(code: object) -> bool:
    return isinstance(code, int) and (code in (408, 429) or code >= 500)


def _retry_after(headers) -> float:
    try:
        return float(headers.get("Retry-After") or 0)
    except ValueError:
        return 0.0


def _http_error(error: urllib.error.HTTPError) -> RuntimeError:
    detail = error.reason
    try:
        with error:
            detail = error_text(json.load(error)["error"])
    except (OSError, ValueError, KeyError, TypeError, http.client.HTTPException):
        pass

    message = f"OpenRouter HTTP {error.code}: {detail}"
    if _retryable(error.code):
        return TransientError(message, _retry_after(error.headers))

    return RuntimeError(message)


def _send(request: urllib.request.Request, timeout: float) -> dict:
    """Send one request, raising TransientError for failures worth repeating."""

    try:
        response = urllib.request.urlopen(request, timeout=timeout)
    except urllib.error.HTTPError as error:
        raise _http_error(error) from error
    except (OSError, http.client.HTTPException) as error:
        raise TransientError(f"OpenRouter request failed: {error}") from error

    with response:
        try:
            result = json.load(response)
        except TimeoutError as error:
            # A non-streaming generation continues, and is billed, after a
            # disconnect: a retry would likely pay for the same slow one again.
            raise RuntimeError(
                f"OpenRouter response took over {timeout} seconds"
            ) from error
        except (OSError, http.client.HTTPException) as error:
            raise TransientError(f"OpenRouter response failed: {error}") from error
        except ValueError as error:
            raise RuntimeError("OpenRouter returned invalid JSON") from error

    if not isinstance(result, dict):
        raise RuntimeError("OpenRouter returned an invalid response")

    # Failures after a provider accepted the request arrive with HTTP 200.
    failure = result.get("error")
    if failure:
        code = failure.get("code") if isinstance(failure, dict) else None
        message = f"OpenRouter error {code}: {error_text(failure)}"
        if _retryable(code):
            raise TransientError(message)
        raise RuntimeError(message)

    return result


def _detached(function, *args) -> asyncio.Future:
    """Run a blocking call in a daemon thread.

    Unlike asyncio.to_thread(), an abandoned call does not delay the process
    exit, so quitting does not wait for a response that can take minutes.
    """

    future: concurrent.futures.Future = concurrent.futures.Future()

    def run() -> None:
        if not future.set_running_or_notify_cancel():
            return
        try:
            future.set_result(function(*args))
        except BaseException as error:
            future.set_exception(error)

    threading.Thread(target=run, daemon=True).start()

    return asyncio.wrap_future(future)


async def completion(model: str, messages: list[dict], **options) -> dict:
    """Request a chat completion, retrying failures that may be transient."""
    request = urllib.request.Request(
        f"{API_URL}/chat/completions",
        data=json.dumps({"model": model, "messages": messages, **options}).encode(),
        headers={
            "Authorization": f"Bearer {api_key()}",
            "Content-Type": "application/json",
            "X-Title": "bfoptimizer",
        },
        method="POST",
    )

    for retry in range(MAX_RETRIES):
        try:
            return await _detached(_send, request, REQUEST_TIMEOUT)
        except TransientError as error:
            # Honor Retry-After, but do not let a bogus value stall the run.
            delay = max(2**retry, min(error.retry_after, 300))
            log.warning(f"{error}, retrying in {delay:g} seconds")
            await asyncio.sleep(delay)

    return await _detached(_send, request, REQUEST_TIMEOUT)


def models() -> dict[str, dict]:
    """Return the public OpenRouter model catalog, keyed by model ID."""

    request = urllib.request.Request(
        f"{API_URL}/models", headers={"X-Title": "bfoptimizer"}
    )
    try:
        return {model["id"]: model for model in _send(request, 60)["data"]}
    except (KeyError, TypeError) as error:
        raise RuntimeError("OpenRouter returned an invalid model list") from error
