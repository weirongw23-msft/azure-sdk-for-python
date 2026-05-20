# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""Async variant of :mod:`azure.storage.blob._shared.session`.

See the sync module for the design overview. This module mirrors that
behavior on top of :class:`azure.core.pipeline.policies.AsyncHTTPPolicy` and
uses :class:`asyncio.Lock` for refresh serialization.
"""

import asyncio
import logging
import time
from typing import Any, Optional, Tuple, TYPE_CHECKING

from azure.core.pipeline.policies import AsyncHTTPPolicy

from .authentication import SharedKeyCredentialPolicy
from .session import (
    FALLBACK_TTL_SECONDS,
    SESSION_ELIGIBLE_CONTEXT_KEY,
    SESSION_INTERNAL_CONTEXT_KEY,
    SESSION_TOKEN_HEADER,
    _CachedSession,
    _CREATE_SESSION_BODY,
    parse_create_session_response,
)

if TYPE_CHECKING:
    from azure.core.pipeline import PipelineRequest, PipelineResponse


_LOGGER = logging.getLogger(__name__)


class AsyncSessionCache:
    """Asyncio-friendly per-container session cache.

    The shape mirrors the sync :class:`SessionCache`. Only one entry is
    retained at a time per client instance.
    """

    def __init__(self) -> None:
        self._entry: Optional[Tuple[str, _CachedSession]] = None

    def get(self, container_name: str) -> Optional[_CachedSession]:
        if self._entry is None:
            return None
        name, entry = self._entry
        if entry.is_expired():
            self._entry = None
            return None
        if name != container_name:
            return None
        return entry

    def put(self, container_name: str, session_token: str, session_key: str, expires_at: float) -> None:
        self._entry = (container_name, _CachedSession(session_token, session_key, expires_at, False))

    def put_fallback(self, container_name: str) -> None:
        expires_at = time.time() + FALLBACK_TTL_SECONDS
        self._entry = (container_name, _CachedSession(None, None, expires_at, True))


class AsyncSessionAuthenticationPolicy(AsyncHTTPPolicy):
    """Async equivalent of :class:`SessionAuthenticationPolicy`."""

    def __init__(self, *, account_name: str, container_name: str, client_ref: Any) -> None:
        super().__init__()
        self._account_name = account_name
        self._container_name = container_name
        self._client_ref = client_ref
        self._cache = AsyncSessionCache()
        self._refresh_lock = asyncio.Lock()

    async def send(self, request: "PipelineRequest") -> "PipelineResponse":
        options = request.context.options
        if options.get(SESSION_INTERNAL_CONTEXT_KEY):
            return await self.next.send(request)
        if not options.get(SESSION_ELIGIBLE_CONTEXT_KEY):
            return await self.next.send(request)
        if request.http_request.method != "GET":
            return await self.next.send(request)

        entry = self._cache.get(self._container_name)
        if entry is None:
            entry = await self._refresh_session()

        if entry is not None and not entry.is_fallback and entry.session_token and entry.session_key:
            self._apply_session_auth(request, entry.session_token, entry.session_key)

        return await self.next.send(request)

    async def _refresh_session(self) -> Optional[_CachedSession]:
        async with self._refresh_lock:
            entry = self._cache.get(self._container_name)
            if entry is not None:
                return entry
            try:
                token, key, expires_at = await self._call_create_session()
            except Exception as ex:  # pylint: disable=broad-except
                _LOGGER.warning(
                    "Session authentication: CreateSession failed for container '%s'; "
                    "falling back to underlying credential for %d seconds. Error: %s",
                    self._container_name,
                    FALLBACK_TTL_SECONDS,
                    ex,
                )
                self._cache.put_fallback(self._container_name)
                return self._cache.get(self._container_name)
            self._cache.put(self._container_name, token, key, expires_at)
            return self._cache.get(self._container_name)

    async def _call_create_session(self) -> Tuple[str, str, float]:
        from .._generated.operations._container_operations import build_create_session_request

        pipeline = self._client_ref._pipeline  # pylint: disable=protected-access
        url = self._client_ref.url
        api_version = self._client_ref.api_version

        http_request = build_create_session_request(
            url=url,
            content=_CREATE_SESSION_BODY,
            version=api_version,
            content_type="application/xml",
        )
        pipeline_response = await pipeline.run(http_request, **{SESSION_INTERNAL_CONTEXT_KEY: True})
        response = pipeline_response.http_response
        if response.status_code not in (200, 201):
            raise RuntimeError(f"CreateSession returned HTTP {response.status_code}")
        # Ensure body is loaded for async transports
        if hasattr(response, "read"):
            try:
                await response.read()
            except TypeError:
                # Some transport responses expose ``read`` synchronously.
                pass
        body = response.body() if hasattr(response, "body") else response.content
        if isinstance(body, str):
            body = body.encode("utf-8")
        return parse_create_session_response(body)

    def _apply_session_auth(self, request: "PipelineRequest", session_token: str, session_key: str) -> None:
        request.http_request.headers[SESSION_TOKEN_HEADER] = session_token
        signer = SharedKeyCredentialPolicy(self._account_name, session_key)
        signer.on_request(request)


