# -------------------------------------------------------------------------
# Copyright (c) Microsoft Corporation. All rights reserved.
# Licensed under the MIT License. See License.txt in the project root for
# license information.
# --------------------------------------------------------------------------
"""Session-based authentication for container-scoped GET blob download operations.

Sessions are an opt-in (``use_session=True`` on ``ContainerClient``) authentication
mode that, for eligible GET blob download requests, replaces the underlying
``TokenCredential`` (Bearer) Authorization header with a SharedKey-style
signature derived from a short-lived session key issued by the service via the
internal CreateSession REST call.

Design highlights:
    * Session-eligible requests are marked via the pipeline context option
      ``_session_eligible`` (only set by ``_download_blob_options``).
    * The policy issues CreateSession on cache miss via the parent client's
      pipeline, tagging the internal request with ``_session_internal=True`` so
      this policy does not recurse on itself.
    * On a "soft" CreateSession failure the cache records a fallback marker for
      5 minutes; during that window the request falls through unchanged so the
      regular bearer-token auth is used.
    * Active sessions are proactively refreshed 60 seconds before expiry.
    * Cache scope is per ``ContainerClient`` instance; only one session entry
      is retained at a time.
"""

import logging
import threading
import time
import xml.etree.ElementTree as ET
from typing import Any, Optional, Tuple, TYPE_CHECKING
from urllib.parse import urlparse

from azure.core.pipeline.policies import HTTPPolicy

from .authentication import SharedKeyCredentialPolicy

if TYPE_CHECKING:
    from azure.core.pipeline import PipelineRequest, PipelineResponse


_LOGGER = logging.getLogger(__name__)

# Proactive refresh window: refresh a cached session this many seconds before
# its server-reported expiration time.
REFRESH_SKEW_SECONDS = 60

# Soft-failure fallback TTL: how long to suppress further CreateSession attempts
# after a non-fatal failure (e.g., service returned 403/409 for this container).
FALLBACK_TTL_SECONDS = 300  # 5 minutes

# Context option names (private; not part of the public API).
SESSION_ELIGIBLE_CONTEXT_KEY = "_session_eligible"
SESSION_INTERNAL_CONTEXT_KEY = "_session_internal"

# Request header that carries the session token to the service.
SESSION_TOKEN_HEADER = "x-ms-session-token"

# CreateSession request body (HMAC is the only currently supported auth type).
_CREATE_SESSION_BODY = (
    b'<?xml version="1.0" encoding="utf-8"?>'
    b"<CreateSessionRequest><AuthenticationType>HMAC</AuthenticationType></CreateSessionRequest>"
)


class _CachedSession:
    """A cached session entry.

    ``credentials`` is ``None`` when the entry represents a cached fallback
    marker (i.e., CreateSession recently soft-failed for this container and we
    should not retry until ``expires_at``).
    """

    __slots__ = ("session_token", "session_key", "expires_at", "is_fallback")

    def __init__(
        self,
        session_token: Optional[str],
        session_key: Optional[str],
        expires_at: float,
        is_fallback: bool = False,
    ) -> None:
        self.session_token = session_token
        self.session_key = session_key
        self.expires_at = expires_at
        self.is_fallback = is_fallback

    def is_expired(self, now: Optional[float] = None) -> bool:
        now = now if now is not None else time.time()
        # Active sessions refresh early (skew); fallback entries expire exactly at TTL.
        skew = 0 if self.is_fallback else REFRESH_SKEW_SECONDS
        return now >= (self.expires_at - skew)


class SessionCache:
    """Thread-safe per-container session cache for the sync stack.

    Only one entry is retained at a time per ``ContainerClient`` instance.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._entry: Optional[Tuple[str, _CachedSession]] = None

    def get(self, container_name: str) -> Optional[_CachedSession]:
        """Returns the live cache entry for ``container_name`` if valid, else ``None``.

        A returned entry may be a fallback marker (``entry.is_fallback`` is True
        and ``entry.session_key`` is ``None``) — the caller should treat that
        as "do not attempt CreateSession; let the underlying credential
        policy handle this request."
        """
        with self._lock:
            if self._entry is None:
                return None
            name, entry = self._entry
            # Evict on expiry, regardless of which container was requested.
            if entry.is_expired():
                self._entry = None
                return None
            # Cache miss on a different container name: do NOT evict the
            # existing entry (a ContainerClient is always scoped to one
            # container, so this primarily guards against misuse).
            if name != container_name:
                return None
            return entry

    def put(self, container_name: str, session_token: str, session_key: str, expires_at: float) -> None:
        with self._lock:
            self._entry = (container_name, _CachedSession(session_token, session_key, expires_at, False))

    def put_fallback(self, container_name: str) -> None:
        expires_at = time.time() + FALLBACK_TTL_SECONDS
        with self._lock:
            self._entry = (container_name, _CachedSession(None, None, expires_at, True))


def parse_create_session_response(body: bytes) -> Tuple[str, str, float]:
    """Parses a CreateSession XML response.

    :returns: A tuple of (session_token, session_key, expires_at_epoch_seconds).
    :raises ValueError: If the response is missing required fields.
    """
    root = ET.fromstring(body)
    # Required fields
    token_el = root.find("Credentials/SessionToken")
    key_el = root.find("Credentials/SessionKey")
    exp_el = root.find("Expiration")
    if token_el is None or token_el.text is None:
        raise ValueError("CreateSession response missing SessionToken")
    if key_el is None or key_el.text is None:
        raise ValueError("CreateSession response missing SessionKey")
    # Expiration is RFC 1123; if missing, conservatively expire after 1 minute.
    if exp_el is not None and exp_el.text:
        try:
            from email.utils import parsedate_to_datetime
            dt = parsedate_to_datetime(exp_el.text)
            expires_at = dt.timestamp()
        except (TypeError, ValueError):
            expires_at = time.time() + 60.0
    else:
        expires_at = time.time() + 60.0
    return token_el.text, key_el.text, expires_at


def container_name_from_url(url: str) -> Optional[str]:
    """Best-effort extraction of the container name from a request URL.

    The first non-empty path segment is the container name for both standard
    (``<account>.blob.core.windows.net/<container>/...``) and path-style
    (``127.0.0.1:10000/<account>/<container>/...``) URLs. For path-style we
    assume the first segment is the account and the second is the container.
    """
    try:
        parsed = urlparse(url)
    except (TypeError, ValueError):
        return None
    segments = [seg for seg in parsed.path.split("/") if seg]
    if not segments:
        return None
    host = (parsed.hostname or "").lower()
    is_path_style = host in ("localhost", "127.0.0.1") or host.startswith("127.")
    if is_path_style:
        return segments[1] if len(segments) >= 2 else None
    return segments[0]


class SessionAuthenticationPolicy(HTTPPolicy):
    """Pipeline policy that applies session authentication to eligible GET requests.

    This policy is installed **after** the bearer-token credential policy so that
    when a session is active, it can overwrite the ``Authorization: Bearer ...``
    header with a SharedKey-style signature using the session key. When no
    session is available (cache miss + fallback in effect, or soft failure),
    the request passes through unchanged and the bearer auth from the previous
    policy remains in place.
    """

    def __init__(self, *, account_name: str, container_name: str, client_ref: Any) -> None:
        super().__init__()
        self._account_name = account_name
        self._container_name = container_name
        # Lazy back-reference to the owning client; used to access the pipeline,
        # url, and api_version at request time (they are not all set yet at the
        # moment this policy is instantiated inside ``_create_pipeline``).
        self._client_ref = client_ref
        self._cache = SessionCache()
        # Guards against concurrent CreateSession requests for the same container.
        self._refresh_lock = threading.Lock()

    def send(self, request: "PipelineRequest") -> "PipelineResponse":
        options = request.context.options
        # Recursion guard: the CreateSession call itself runs through the same
        # pipeline — let it pass through with Bearer auth from the prior policy.
        if options.get(SESSION_INTERNAL_CONTEXT_KEY):
            return self.next.send(request)

        if not options.get(SESSION_ELIGIBLE_CONTEXT_KEY):
            return self.next.send(request)

        if request.http_request.method != "GET":
            return self.next.send(request)

        entry = self._cache.get(self._container_name)
        if entry is None:
            entry = self._refresh_session()

        if entry is not None and not entry.is_fallback and entry.session_token and entry.session_key:
            self._apply_session_auth(request, entry.session_token, entry.session_key)

        return self.next.send(request)

    def _refresh_session(self) -> Optional[_CachedSession]:
        """Issues CreateSession (with serialization across concurrent refreshes)."""
        with self._refresh_lock:
            # Re-check under the lock in case another caller populated the cache.
            entry = self._cache.get(self._container_name)
            if entry is not None:
                return entry
            try:
                token, key, expires_at = self._call_create_session()
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

    def _call_create_session(self) -> Tuple[str, str, float]:
        # Import the request builder lazily to avoid generated-layer import
        # cycles at module load time.
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
        # Tag this internal call so this policy doesn't try to apply session
        # auth to the CreateSession request itself.
        pipeline_response = pipeline.run(http_request, **{SESSION_INTERNAL_CONTEXT_KEY: True})
        response = pipeline_response.http_response
        if response.status_code not in (200, 201):
            raise RuntimeError(
                f"CreateSession returned HTTP {response.status_code}"
            )
        body = response.body() if hasattr(response, "body") else response.content
        if isinstance(body, str):
            body = body.encode("utf-8")
        return parse_create_session_response(body)

    def _apply_session_auth(self, request: "PipelineRequest", session_token: str, session_key: str) -> None:
        # Add session token to headers BEFORE signing so the canonical headers
        # include it.
        request.http_request.headers[SESSION_TOKEN_HEADER] = session_token
        # Re-sign the request with the session key, overwriting any prior
        # Authorization header (e.g., the Bearer token set by the credential
        # policy). The SessionKey is used as the HMAC key under the SharedKey
        # protocol; account name is the signer identity.
        signer = SharedKeyCredentialPolicy(self._account_name, session_key)
        signer.on_request(request)





