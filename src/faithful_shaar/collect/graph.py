# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""A read-only Microsoft Graph client built on the standard library.

What it guarantees, and the tests prove:

- Every request is an HTTP GET. The client has no way to name another method.
- The access token goes only to the configured Graph host, over HTTPS with the
  default certificate verification. Redirects are never followed, so a redirect
  cannot carry the token elsewhere, and a paging link (``@odata.nextLink``) is
  followed only when its scheme and host equal the base URL's.
- Throttling (HTTP 429, 503 and 504) is retried at most five times, waiting as
  ``Retry-After`` says, within a cap.
- Nothing that was not read is reported as read: a failure that stops one request
  raises :class:`GraphGap` with a reason, and the caller records a gap. Only a
  rejected token (HTTP 401) stops collection, with ``CollectionError``.
- The token and every secret this process resolved are redacted from every reason
  and message.
"""

from __future__ import annotations

import http.client
import json
import re
import time
import urllib.error
import urllib.request
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from typing import TYPE_CHECKING, Any, Protocol
from urllib.parse import quote, urlencode, urlsplit

from faithful_shaar import __version__
from faithful_shaar.collect import secrets
from faithful_shaar.errors import CollectionError

if TYPE_CHECKING:
    from collections.abc import Callable, Mapping

MAX_RETRIES = 5
MAX_DELAY = 60.0
BACKOFF_START = 1.0
MAX_RESPONSE_BYTES = 16 * 1024 * 1024
MAX_ERROR_BYTES = 64 * 1024
MAX_PAGES = 500
TIMEOUT_SECONDS = 60.0
PAGE_SIZE = "999"
API_VERSION = "/v1.0"

_RETRY_STATUSES = frozenset({429, 503, 504})
_ERROR_CODE = re.compile(r"[A-Za-z0-9_.-]{1,64}")
_HTTP_UNAUTHORIZED = 401
_HTTP_FORBIDDEN = 403
_HTTP_NOT_FOUND = 404
_HTTP_OK = range(200, 300)


@dataclass(frozen=True)
class Cloud:
    """A national cloud: the Graph host and the sign-in authority that goes with it."""

    name: str
    graph_host: str
    authority: str  # the name of the attribute of azure.identity.AzureAuthorityHosts


CLOUDS: dict[str, Cloud] = {
    "global": Cloud("global", "graph.microsoft.com", "AZURE_PUBLIC_CLOUD"),
    "usgov": Cloud("usgov", "graph.microsoft.us", "AZURE_GOVERNMENT"),
    "usgovdod": Cloud("usgovdod", "dod-graph.microsoft.us", "AZURE_GOVERNMENT"),
    "china": Cloud("china", "microsoftgraph.chinacloudapi.cn", "AZURE_CHINA"),
}


class GraphGap(Exception):  # noqa: N818 - a gap in what was read, not an error to fix
    """Something could not be read. The reason is safe to print and to write."""

    def __init__(self, reason: str, status: int = 0) -> None:
        """Keep ``reason`` with every known secret removed, and the HTTP status if any."""
        self.reason = secrets.redact(reason)
        self.status = status
        super().__init__(self.reason)


class Credential(Protocol):
    """The part of an azure-identity credential this client uses."""

    def get_token(self, *scopes: str) -> Any:
        """Return an object with a ``token`` attribute."""


@dataclass(frozen=True)
class Pages:
    """What a paged listing returned, and why it stopped early (empty when it did not)."""

    items: list[dict[str, Any]]
    error: str = ""


@dataclass(frozen=True)
class _Reply:
    status: int
    retry_after: str | None
    body: bytes


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    """Refuse every redirect, so the Authorization header never follows one."""

    def redirect_request(self, *args: Any, **kwargs: Any) -> None:  # noqa: ARG002
        return None


def _build_opener() -> urllib.request.OpenerDirector:
    """The default opener (proxy settings, verified HTTPS) without redirects."""
    return urllib.request.build_opener(_NoRedirect)


def retry_delay(retry_after: str | None, attempt: int, now: datetime) -> float:
    """Seconds to wait before retry number ``attempt`` (from 0).

    ``retry_after`` is the header value: whole seconds or an HTTP date. A missing
    or unreadable value falls back to doubling backoff. The result is capped.
    """
    backoff = float(min(BACKOFF_START * 2**attempt, MAX_DELAY))
    if retry_after is None:
        return backoff
    text = retry_after.strip()
    if text.isascii() and text.isdigit():
        seconds = float(int(text))
    else:
        try:
            when = parsedate_to_datetime(text)
        except (TypeError, ValueError):
            return backoff
        if when.tzinfo is None:
            when = when.replace(tzinfo=UTC)
        seconds = (when - now).total_seconds()
    return float(min(max(seconds, 0.0), MAX_DELAY))


def odata_string(value: str) -> str:
    """Quote ``value`` as an OData string literal: single quotes are doubled."""
    return "'" + value.replace("'", "''") + "'"


class GraphClient:
    """Read JSON from Microsoft Graph v1.0 with a token for one national cloud."""

    def __init__(
        self,
        cloud: Cloud,
        credential: Credential,
        *,
        sleep: Callable[[float], None] = time.sleep,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
        timeout: float = TIMEOUT_SECONDS,
    ) -> None:
        """Prepare a client; nothing is requested until the first ``get``."""
        self.cloud = cloud
        self.host = cloud.graph_host
        self.base = f"https://{cloud.graph_host}{API_VERSION}"
        self._scope = f"https://{cloud.graph_host}/.default"
        self._credential = credential
        self._sleep = sleep
        self._now = now
        self._timeout = timeout
        self._opener = _build_opener()

    def get(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        needs: str = "",
    ) -> dict[str, Any]:
        """GET ``path`` (starting with ``/``) under the v1.0 base and return the JSON object.

        Raises:
            GraphGap: The request could not be answered; the reason says why.
            CollectionError: Graph rejected the token (HTTP 401) or sign-in failed.
        """
        url = self.base + path
        if params:
            url += "?" + urlencode(params, quote_via=quote, safe="$,()")
        return self._fetch(url, needs)

    def pages(
        self,
        path: str,
        params: Mapping[str, str] | None = None,
        *,
        needs: str = "",
        top: bool = True,
    ) -> Pages:
        """Read every page of a listing. A failed page keeps what came before it.

        The ``error`` of the result is empty only when the whole listing was read.
        ``top`` asks for the largest page; leave it off for listings that may not
        accept ``$top``.
        """
        merged = {**({"$top": PAGE_SIZE} if top else {}), **(params or {})}
        items: list[dict[str, Any]] = []
        url = self.base + path + "?" + urlencode(merged, quote_via=quote, safe="$,()")
        seen: set[str] = set()
        for _ in range(MAX_PAGES):
            seen.add(url)
            try:
                payload = self._fetch(url, needs)
            except GraphGap as gap:
                return Pages(items, gap.reason)
            values = payload.get("value")
            if not isinstance(values, list):
                return Pages(items, "the response has no list of values")
            items.extend(v for v in values if isinstance(v, dict))
            link = payload.get("@odata.nextLink")
            if link is None:
                return Pages(items)
            if not isinstance(link, str) or not self._same_origin(link):
                return Pages(items, "refused a paging link that does not stay on the Graph host")
            if link in seen:
                return Pages(items, "the paging links repeat")
            url = link
        return Pages(items, f"stopped after {MAX_PAGES} pages")

    def _same_origin(self, url: str) -> bool:
        try:
            parts = urlsplit(url)
        except ValueError:
            return False
        return (
            parts.scheme == "https"
            and parts.netloc.lower() == self.host
            and (parts.path + "/").startswith(API_VERSION + "/")
        )

    def _token(self) -> str:
        try:
            token = str(self._credential.get_token(self._scope).token)
        except Exception as exc:  # noqa: BLE001 - azure-identity raises many types
            msg = f"sign-in failed ({type(exc).__name__}): {secrets.redact(str(exc))}"
            raise CollectionError(msg) from None
        if not token:
            msg = "sign-in returned no access token"
            raise CollectionError(msg)
        secrets.remember(token)
        return token

    def _fetch(self, url: str, needs: str) -> dict[str, Any]:
        token = self._token()
        for attempt in range(MAX_RETRIES):
            reply = self._once(url, token)
            if reply.status not in _RETRY_STATUSES:
                return self._interpret(reply, needs)
            self._sleep(retry_delay(reply.retry_after, attempt, self._now()))
        return self._interpret(self._once(url, token), needs)

    def _once(self, url: str, token: str) -> _Reply:
        request = urllib.request.Request(  # noqa: S310 - https and the Graph host only
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/json",
                "User-Agent": f"shaar/{__version__}",
            },
        )
        try:
            with self._opener.open(request, timeout=self._timeout) as response:
                body = response.read(MAX_RESPONSE_BYTES + 1)
                return _Reply(int(response.status), None, body)
        except urllib.error.HTTPError as exc:
            try:
                return _Reply(exc.code, exc.headers.get("Retry-After"), exc.read(MAX_ERROR_BYTES))
            finally:
                exc.close()
        except (OSError, http.client.HTTPException) as exc:
            msg = f"the request failed ({type(exc).__name__})"
            raise GraphGap(msg) from None

    def _interpret(self, reply: _Reply, needs: str) -> dict[str, Any]:
        status = reply.status
        if status in _HTTP_OK:
            return _parse(reply.body)
        if status == _HTTP_UNAUTHORIZED:
            msg = (
                "Microsoft Graph rejected the access token (HTTP 401). Check the tenant, "
                "client id and credential, and that the application has admin consent"
            )
            raise CollectionError(msg)
        raise GraphGap(_failure(status, needs, _error_code(reply.body)), status)


def _failure(status: int, needs: str, code: str) -> str:
    suffix = f" [{code}]" if code else ""
    if status == _HTTP_FORBIDDEN:
        wanted = f"; the application needs {needs} (application permission, admin consent)"
        return f"access denied (HTTP 403){suffix}{wanted if needs else ''}"
    if status == _HTTP_NOT_FOUND:
        return f"not found (HTTP 404){suffix}"
    if status in _RETRY_STATUSES:
        return f"still throttled after {MAX_RETRIES} retries (HTTP {status})"
    return f"Microsoft Graph answered HTTP {status}{suffix}"


def _parse(body: bytes) -> dict[str, Any]:
    if len(body) > MAX_RESPONSE_BYTES:
        msg = f"the response is larger than {MAX_RESPONSE_BYTES // (1024 * 1024)} MiB"
        raise GraphGap(msg)
    try:
        payload = json.loads(body)
    except ValueError:
        msg = "the response is not valid JSON"
        raise GraphGap(msg) from None
    if not isinstance(payload, dict):
        msg = "the response is not a JSON object"
        raise GraphGap(msg)
    return payload


def _error_code(body: bytes) -> str:
    """The short ``error.code`` Graph sends, when it looks like a code (never free text)."""
    try:
        payload = json.loads(body)
        code = payload["error"]["code"]
    except (ValueError, KeyError, TypeError):
        return ""
    return code if isinstance(code, str) and _ERROR_CODE.fullmatch(code) else ""
