# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Tests for the Entra ID collector, its Graph client, and its output file.

No test touches the network: the urllib opener is replaced by a fake Graph, and
azure-identity by a fake credential.
"""

from __future__ import annotations

import argparse
import hashlib
import http.client
import io
import json
import os
import socket
import stat
import sys
import types
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import parse_qs, urlsplit

import azure.identity as real_identity
import pytest

from faithful_shaar import __version__
from faithful_shaar.collect import entra, fileout, graph, secrets
from faithful_shaar.collect.graph import CLOUDS, GraphClient, GraphGap
from faithful_shaar.errors import CollectionError

if TYPE_CHECKING:
    from collections.abc import Iterator

TENANT = "00000000-0000-4000-8000-000000000000"
CLIENT = "00000000-0000-4000-8000-0000000000aa"
TOKEN = "tok-Zq81-not-a-real-token"  # noqa: S105 - synthetic
RESOLVED = secrets._resolved  # noqa: SLF001 - restored after each test
build_real_opener = graph._build_opener  # noqa: SLF001
NoRedirect = graph._NoRedirect  # noqa: SLF001
NOW = datetime(2026, 11, 12, 9, 30, 0, tzinfo=UTC)


def oid(n: int) -> str:
    return f"00000000-0000-4000-8000-{n:012d}"


# --- a fake Graph -------------------------------------------------------------------


@dataclass
class Reply:
    """One canned answer."""

    status: int = 200
    body: Any = field(default_factory=dict)
    headers: dict[str, str] = field(default_factory=dict)

    def raw(self) -> bytes:
        if isinstance(self.body, bytes):
            return self.body
        return json.dumps(self.body).encode()


class FakeResponse:
    """What urlopen returns: a context manager with status and read."""

    def __init__(self, reply: Reply) -> None:
        self.status = reply.status
        self._data = reply.raw()

    def __enter__(self) -> FakeResponse:  # noqa: D105
        return self

    def __exit__(self, *_: object) -> None:  # noqa: D105
        return None

    def read(self, size: int = -1) -> bytes:
        return self._data if size < 0 else self._data[:size]


@dataclass
class Recorded:
    """One request as the fake saw it."""

    method: str
    url: str
    headers: dict[str, str]
    has_data: bool
    timeout: float | None


class FakeGraph:
    """Answers by path (the part after /v1.0). A list is a sequence; the last repeats."""

    def __init__(self) -> None:
        self.routes: dict[str, Any] = {}
        self.requests: list[Recorded] = []
        self.host = CLOUDS["global"].graph_host

    def add(self, path: str, *replies: Reply | dict[str, Any]) -> None:
        self.routes[path] = [r if isinstance(r, Reply) else Reply(200, r) for r in replies]

    def paths(self) -> list[str]:
        return [urlsplit(r.url).path.removeprefix("/v1.0") for r in self.requests]

    def queries(self, path: str) -> list[dict[str, list[str]]]:
        return [
            parse_qs(urlsplit(r.url).query)
            for r in self.requests
            if urlsplit(r.url).path.removeprefix("/v1.0") == path
        ]

    def open(self, request: urllib.request.Request, timeout: float | None = None) -> FakeResponse:
        self.requests.append(
            Recorded(
                request.get_method(),
                request.full_url,
                {k.lower(): v for k, v in request.header_items()},
                request.data is not None,
                timeout,
            )
        )
        path = urlsplit(request.full_url).path.removeprefix("/v1.0")
        reply = self._reply(path)
        if reply.status >= 400:
            raise _http_error(request.full_url, reply)
        return FakeResponse(reply)

    def _reply(self, path: str) -> Reply:
        queue = self.routes.get(path)
        if queue is None and path.startswith("/users/"):
            return Reply(200, {"id": path.rsplit("/", 1)[1]})
        if queue is None:
            return Reply(404, {"error": {"code": "Request_ResourceNotFound"}})
        reply: Reply = queue.pop(0) if len(queue) > 1 else queue[0]
        return reply


def _http_error(url: str, reply: Reply) -> urllib.error.HTTPError:
    message = http.client.HTTPMessage()
    for key, value in reply.headers.items():
        message[key] = value
    return urllib.error.HTTPError(url, reply.status, "error", message, io.BytesIO(reply.raw()))


@dataclass
class Token:
    """An access token object."""

    token: str


class FakeCredential:
    """An azure-identity credential that returns a fixed token."""

    def __init__(self, token: str = TOKEN) -> None:
        self.token = token
        self.scopes: list[tuple[str, ...]] = []

    def get_token(self, *scopes: str) -> Token:
        self.scopes.append(scopes)
        return Token(self.token)


@pytest.fixture(autouse=True)
def _clean_secrets() -> Iterator[None]:
    before = set(RESOLVED)
    yield
    RESOLVED.clear()
    RESOLVED.update(before)


@pytest.fixture
def fake(monkeypatch: pytest.MonkeyPatch) -> Iterator[FakeGraph]:
    """A fake Graph. Afterwards, every request it saw must have been a safe GET."""
    fake_graph = FakeGraph()
    monkeypatch.setattr(graph, "_build_opener", lambda: fake_graph)
    yield fake_graph
    for request in fake_graph.requests:
        parts = urlsplit(request.url)
        assert request.method == "GET"
        assert not request.has_data
        assert parts.scheme == "https"
        assert parts.netloc == fake_graph.host
        assert request.headers["authorization"] == f"Bearer {TOKEN}"
        assert request.headers["accept"] == "application/json"
        assert request.headers["user-agent"] == f"shaar/{__version__}"
        assert request.timeout is not None


@pytest.fixture
def sleeps() -> list[float]:
    return []


@pytest.fixture
def client(fake: FakeGraph, sleeps: list[float]) -> GraphClient:  # noqa: ARG001 - installs the fake
    return GraphClient(CLOUDS["global"], FakeCredential(), sleep=sleeps.append, now=lambda: NOW)


def read_export(data: bytes) -> list[dict[str, Any]]:
    assert data.endswith(b"\n")
    return [json.loads(line) for line in data.decode().split("\n")[:-1]]


def run(client: GraphClient, scope: entra.Scope) -> entra.Export:
    return entra.collect(client, TENANT, scope, "2026-11-12T09:30:00Z")


def kinds(export: entra.Export, key: str) -> list[dict[str, Any]]:
    return [r[key] for r in read_export(entra.render(export)) if key in r]


def user(n: int, name: str, **more: Any) -> dict[str, Any]:
    return {
        "@odata.type": "#microsoft.graph.user",
        "id": oid(n),
        "displayName": name,
        "userPrincipalName": f"{name.split(' ', 1)[0].lower()}{n}@corp.example",
        "mail": f"{name.split(' ', 1)[0].lower()}{n}@corp.example",
        "accountEnabled": True,
        "userType": "Member",
        **more,
    }


def group(n: int, name: str) -> dict[str, Any]:
    return {"@odata.type": "#microsoft.graph.group", "id": oid(n), "displayName": name}


def value(*items: dict[str, Any], **more: Any) -> dict[str, Any]:
    return {"value": list(items), **more}


# --- graph client: paging -----------------------------------------------------------


def test_get_sends_only_a_get_with_the_token_and_asks_for_json(
    client: GraphClient, fake: FakeGraph
) -> None:
    fake.add("/groups/x", {"id": "x"})
    assert client.get("/groups/x", {"$select": "id,displayName"}) == {"id": "x"}
    request = fake.requests[0]
    assert request.url == "https://graph.microsoft.com/v1.0/groups/x?$select=id,displayName"
    assert request.timeout == graph.TIMEOUT_SECONDS


def test_query_values_are_percent_encoded(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/groups", {"value": []})
    client.get("/groups", {"$filter": "displayName eq 'a b&c'"})
    assert "a%20b%26c" in fake.requests[0].url
    assert "%27a" in fake.requests[0].url


def test_pages_follow_next_links_on_the_graph_host(client: GraphClient, fake: FakeGraph) -> None:
    next_link = "https://graph.microsoft.com/v1.0/groups?$skiptoken=abc"
    fake.add(
        "/groups",
        {"value": [{"id": "1"}, "not an object"], "@odata.nextLink": next_link},
        value({"id": "2"}),
    )
    result = client.pages("/groups", {"$select": "id"})
    assert [i["id"] for i in result.items] == ["1", "2"]
    assert result.error == ""
    assert fake.queries("/groups")[0]["$top"] == ["999"]
    assert fake.requests[1].url == next_link


def test_pages_can_leave_out_top(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/x", value())
    client.pages("/x", top=False)
    assert "$top" not in fake.requests[0].url
    client.pages("/x")
    assert "%24top" in fake.requests[1].url or "$top=999" in fake.requests[1].url


@pytest.mark.parametrize(
    "link",
    [
        "https://evil.example/v1.0/groups?$skiptoken=1",
        "http://graph.microsoft.com/v1.0/groups?$skiptoken=1",
        "https://graph.microsoft.com.evil.example/v1.0/groups",
        "https://graph.microsoft.com@evil.example/v1.0/groups",
        "https://graph.microsoft.com:444/v1.0/groups",
        "https://graph.microsoft.com/beta/groups",
        "https://graph.microsoft.com/v1.0evil/groups",
        "https://[::1/v1.0/groups",
        "ftp://graph.microsoft.com/v1.0/groups",
        42,
    ],
)
def test_a_next_link_off_the_graph_host_is_refused_and_never_requested(
    client: GraphClient, fake: FakeGraph, link: object
) -> None:
    fake.add("/groups", {"value": [{"id": "1"}], "@odata.nextLink": link})
    result = client.pages("/groups")
    assert [i["id"] for i in result.items] == ["1"]
    assert "does not stay on the Graph host" in result.error
    assert len(fake.requests) == 1


def test_paging_links_that_repeat_stop(client: GraphClient, fake: FakeGraph) -> None:
    link = "https://graph.microsoft.com/v1.0/groups?$skiptoken=1"
    fake.add("/groups", {"value": [], "@odata.nextLink": link})
    result = client.pages("/groups")
    assert result.error == "the paging links repeat"
    assert len(fake.requests) == 2


def test_the_page_limit_bounds_paging(
    client: GraphClient, fake: FakeGraph, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(graph, "MAX_PAGES", 3)
    pages = [
        {"value": [{"id": str(n)}], "@odata.nextLink": f"https://graph.microsoft.com/v1.0/g?p={n}"}
        for n in range(10)
    ]
    fake.add("/g", *pages)
    result = client.pages("/g")
    assert result.error == "stopped after 3 pages"
    assert len(result.items) == 3


def test_a_failed_page_keeps_the_pages_before_it(client: GraphClient, fake: FakeGraph) -> None:
    link = "https://graph.microsoft.com/v1.0/g?p=2"
    fake.add("/g", {"value": [{"id": "1"}], "@odata.nextLink": link}, Reply(500))
    result = client.pages("/g")
    assert [i["id"] for i in result.items] == ["1"]
    assert "HTTP 500" in result.error


def test_a_page_without_values_is_an_error(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/g", {"nope": 1})
    assert client.pages("/g").error == "the response has no list of values"


# --- graph client: throttling and errors --------------------------------------------


def test_retry_after_in_seconds_is_honored(
    client: GraphClient, fake: FakeGraph, sleeps: list[float]
) -> None:
    fake.add("/g", Reply(429, {}, {"Retry-After": "7"}), Reply(200, {"ok": 1}))
    assert client.get("/g") == {"ok": 1}
    assert sleeps == [7.0]


def test_retry_after_as_an_http_date_is_honored(
    client: GraphClient, fake: FakeGraph, sleeps: list[float]
) -> None:
    fake.add(
        "/g",
        Reply(503, {}, {"Retry-After": "Thu, 12 Nov 2026 09:30:12 GMT"}),
        Reply(200, {"ok": 1}),
    )
    client.get("/g")
    assert sleeps == [12.0]


def test_a_missing_retry_after_backs_off_by_doubling_to_a_cap(
    client: GraphClient, fake: FakeGraph, sleeps: list[float]
) -> None:
    fake.add("/g", *[Reply(504)] * 5, Reply(200, {"ok": 1}))
    client.get("/g")
    assert sleeps == [1.0, 2.0, 4.0, 8.0, 16.0]


def test_throttling_gives_up_after_five_retries(
    client: GraphClient, fake: FakeGraph, sleeps: list[float]
) -> None:
    fake.add("/g", Reply(429, {}, {"Retry-After": "3"}))
    with pytest.raises(GraphGap, match="still throttled after 5 retries") as caught:
        client.get("/g")
    assert caught.value.status == 429
    assert len(fake.requests) == 6
    assert sleeps == [3.0] * 5


@pytest.mark.parametrize(
    ("header", "attempt", "expected"),
    [
        (None, 0, 1.0),
        (None, 20, graph.MAX_DELAY),
        ("0", 0, 0.0),
        (" 15 ", 0, 15.0),
        ("99999", 0, graph.MAX_DELAY),
        ("soon", 2, 4.0),
        ("-5", 0, 1.0),
        ("Thu, 12 Nov 2026 09:00:00 GMT", 0, 0.0),
        ("Thu, 12 Nov 2026 09:30:30 -0000", 0, 30.0),
        ("Thu, 12 Nov 2026 11:30:00 GMT", 0, graph.MAX_DELAY),
        ("", 0, 1.0),
    ],
)
def test_retry_delay(header: str | None, attempt: int, expected: float) -> None:
    assert graph.retry_delay(header, attempt, NOW) == expected


def test_401_stops_collection_without_showing_the_token(
    client: GraphClient, fake: FakeGraph
) -> None:
    fake.add("/g", Reply(401, {"error": {"code": "InvalidAuthenticationToken", "message": TOKEN}}))
    with pytest.raises(CollectionError, match="rejected the access token") as caught:
        client.get("/g")
    assert TOKEN not in str(caught.value)


def test_403_names_the_permission(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/g", Reply(403, {"error": {"code": "Authorization_RequestDenied"}}))
    with pytest.raises(GraphGap) as caught:
        client.get("/g", needs="GroupMember.Read.All")
    assert caught.value.status == 403
    assert "GroupMember.Read.All" in caught.value.reason
    assert "[Authorization_RequestDenied]" in caught.value.reason


def test_403_without_a_named_permission(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/g", Reply(403, b"<html>no</html>"))
    with pytest.raises(GraphGap) as caught:
        client.get("/g")
    assert caught.value.reason == "access denied (HTTP 403)"


def test_404_and_other_errors_are_gaps(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/g", Reply(404, {"error": {"code": "Request_ResourceNotFound"}}))
    with pytest.raises(GraphGap, match=r"not found \(HTTP 404\)"):
        client.get("/g")
    fake.add("/h", Reply(500, {"error": {"code": "x y z", "message": "free text"}}))
    with pytest.raises(GraphGap) as caught:
        client.get("/h")
    assert caught.value.reason == "Microsoft Graph answered HTTP 500"
    fake.add("/i", Reply(400, {"error": ["not", "a", "dict"]}))
    with pytest.raises(GraphGap, match="HTTP 400"):
        client.get("/i")
    fake.add("/j", Reply(400, {"error": {"code": 7}}))
    with pytest.raises(GraphGap, match="HTTP 400"):
        client.get("/j")


def test_bad_json_is_a_gap(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/g", Reply(200, b"{not json"))
    with pytest.raises(GraphGap, match="not valid JSON"):
        client.get("/g")
    fake.add("/h", Reply(200, b"\xff\xfe"))
    with pytest.raises(GraphGap, match="not valid JSON"):
        client.get("/h")
    fake.add("/i", Reply(200, b"[1]"))
    with pytest.raises(GraphGap, match="not a JSON object"):
        client.get("/i")
    fake.add("/j", Reply(204, b""))
    with pytest.raises(GraphGap, match="not valid JSON"):
        client.get("/j")


def test_an_oversized_response_is_a_gap(
    client: GraphClient, fake: FakeGraph, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(graph, "MAX_RESPONSE_BYTES", 10)
    fake.add("/g", Reply(200, b'{"padding": "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"}'))
    with pytest.raises(GraphGap, match="larger than 0 MiB"):
        client.get("/g")


@pytest.mark.parametrize(
    "error",
    [
        urllib.error.URLError("dns failure holding tok"),
        TimeoutError("read timed out"),
        socket.gaierror("no such host"),
        http.client.IncompleteRead(b"abc"),
        http.client.RemoteDisconnected("closed"),
    ],
)
def test_network_failures_are_gaps_without_the_library_text(
    client: GraphClient, fake: FakeGraph, error: Exception
) -> None:
    def boom(*_: object, **__: object) -> None:
        raise error

    fake.open = boom  # type: ignore[method-assign,assignment]
    with pytest.raises(GraphGap) as caught:
        client.get("/g")
    assert caught.value.reason == f"the request failed ({type(error).__name__})"


def test_gap_reasons_never_hold_a_remembered_secret() -> None:
    secrets.remember("hunter2-secret")
    assert "hunter2" not in GraphGap("failed with hunter2-secret inside").reason


def test_sign_in_failure_is_a_collection_error_with_secrets_removed(fake: FakeGraph) -> None:
    secrets.remember("s3cr3t-value")

    class Broken:
        def get_token(self, *scopes: str) -> Token:
            raise RuntimeError("bad credential s3cr3t-value")

    with pytest.raises(CollectionError, match=r"sign-in failed \(RuntimeError\)") as caught:
        GraphClient(CLOUDS["global"], Broken()).get("/g")
    assert "s3cr3t-value" not in str(caught.value)
    assert not fake.requests


@pytest.mark.usefixtures("fake")
def test_an_empty_token_is_refused() -> None:
    with pytest.raises(CollectionError, match="no access token"):
        GraphClient(CLOUDS["global"], FakeCredential("")).get("/g")


def test_the_token_is_remembered_so_it_is_redacted(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/g", {})
    client.get("/g")
    assert secrets.redact(f"x {TOKEN} y") == f"x {secrets.REDACTED} y"


def test_the_opener_never_follows_redirects() -> None:
    opener: Any = build_real_opener()
    assert any(isinstance(h, NoRedirect) for h in opener.handlers)
    assert any(isinstance(h, urllib.request.ProxyHandler) for h in opener.handlers)
    request = urllib.request.Request("https://graph.microsoft.com/v1.0/x")
    handler: Any = NoRedirect()
    answer = handler.redirect_request(request, None, 302, "Found", {}, "https://evil.example/")
    assert answer is None


# --- clouds and sign-in -------------------------------------------------------------


@pytest.mark.parametrize(
    ("cloud", "host", "authority_host"),
    [
        ("global", "graph.microsoft.com", "login.microsoftonline.com"),
        ("usgov", "graph.microsoft.us", "login.microsoftonline.us"),
        ("usgovdod", "dod-graph.microsoft.us", "login.microsoftonline.us"),
        ("china", "microsoftgraph.chinacloudapi.cn", "login.chinacloudapi.cn"),
    ],
)
def test_each_cloud_uses_its_graph_host_scope_and_authority(
    cloud: str, host: str, authority_host: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    assert CLOUDS[cloud].graph_host == host
    assert getattr(real_identity.AzureAuthorityHosts, CLOUDS[cloud].authority) == authority_host

    fake_graph = FakeGraph()
    fake_graph.host = host
    fake_graph.add("/x", {})
    monkeypatch.setattr(graph, "_build_opener", lambda: fake_graph)
    credential = FakeCredential()
    GraphClient(CLOUDS[cloud], credential).get("/x")
    assert credential.scopes == [(f"https://{host}/.default",)]
    assert fake_graph.requests[0].url == f"https://{host}/v1.0/x"
    assert fake_graph.requests[0].headers["authorization"] == f"Bearer {TOKEN}"


class FakeIdentity(types.ModuleType):
    """A stand-in for azure.identity that records how credentials were built."""

    class AzureAuthorityHosts:  # noqa: D106
        AZURE_PUBLIC_CLOUD = "login.example-public"
        AZURE_GOVERNMENT = "login.example-gov"
        AZURE_CHINA = "login.example-china"

    def __init__(self) -> None:
        super().__init__("azure.identity")
        self.built: list[tuple[str, tuple[Any, ...], dict[str, Any]]] = []
        outer = self

        def make(label: str) -> type:
            class Credential(FakeCredential):
                def __init__(self, *args: Any, **kwargs: Any) -> None:
                    super().__init__()
                    outer.built.append((label, args, kwargs))

            return Credential

        self.CertificateCredential = make("certificate")
        self.ClientSecretCredential = make("secret")
        self.DeviceCodeCredential = make("device")


@pytest.fixture
def identity(monkeypatch: pytest.MonkeyPatch) -> FakeIdentity:
    module = FakeIdentity()
    monkeypatch.setitem(sys.modules, "azure.identity", module)
    return module


def test_certificate_sign_in(identity: FakeIdentity, tmp_path: Path) -> None:
    pem = tmp_path / "app.pem"
    pem.write_text("synthetic")
    sign_in = entra.SignIn(
        TENANT,
        CLIENT,
        CLOUDS["usgovdod"],
        certificate=pem,
        certificate_password="pw",  # noqa: S106
    )
    entra.build_credential(sign_in)
    label, args, kwargs = identity.built[0]
    assert (label, args) == ("certificate", (TENANT, CLIENT))
    assert kwargs == {
        "certificate_path": str(pem),
        "password": "pw",
        "authority": "login.example-gov",
    }


def test_client_secret_sign_in(identity: FakeIdentity) -> None:
    sign_in = entra.SignIn(TENANT, CLIENT, CLOUDS["china"], client_secret="the-secret")  # noqa: S106
    entra.build_credential(sign_in)
    assert identity.built == [
        ("secret", (TENANT, CLIENT, "the-secret"), {"authority": "login.example-china"})
    ]


def test_device_code_sign_in_prints_the_message_to_stderr(
    identity: FakeIdentity, capsys: pytest.CaptureFixture[str]
) -> None:
    entra.build_credential(entra.SignIn(TENANT, CLIENT, CLOUDS["global"], device_code=True))
    _, _, kwargs = identity.built[0]
    assert kwargs["authority"] == "login.example-public"
    assert kwargs["client_id"] == CLIENT
    assert kwargs["tenant_id"] == TENANT
    kwargs["prompt_callback"]("https://login.example/device", "ABCD-1234", NOW)
    captured = capsys.readouterr()
    assert captured.out == ""
    assert "https://login.example/device" in captured.err
    assert "ABCD-1234" in captured.err
    assert "2026-11-12 09:30:00 UTC" in captured.err


def test_missing_extra_names_the_install_command(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setitem(sys.modules, "azure.identity", None)
    with pytest.raises(CollectionError) as caught:
        entra.build_credential(entra.SignIn(TENANT, CLIENT, CLOUDS["global"]))
    assert "pip install 'faithful-shaar[entra]'" in str(caught.value)


# --- collection: groups -------------------------------------------------------------


def nested_tenant(fake: FakeGraph) -> None:
    """Tier0 Admins holds Avery directly and Server Ops, which holds Jordan and Deep.

    Deep holds Casey and, in a cycle, Tier0 Admins again.
    """
    tier0, ops, deep = group(1, "Tier0 Admins"), group(2, "Server Ops"), group(3, "Deep")
    fake.add(f"/groups/{oid(1)}", {**tier0, "securityEnabled": True})
    avery = user(11, "Avery Example")
    jordan = user(12, "Jordan Example")
    casey = user(13, "Casey Example", userType="Guest")
    fake.add(f"/groups/{oid(1)}/owners", value(avery))
    fake.add(f"/groups/{oid(1)}/members", value(avery, ops))
    fake.add(f"/groups/{oid(1)}/transitiveMembers", value(avery, ops, deep, jordan, casey))
    fake.add(f"/groups/{oid(2)}/members", value(jordan, deep))
    fake.add(f"/groups/{oid(3)}/members", value(casey, tier0))
    fake.add(
        f"/users/{oid(11)}",
        {"id": oid(11), "manager": {**user(20, "Morgan Example"), "accountEnabled": True}},
    )
    fake.add(f"/users/{oid(12)}", Reply(500))
    fake.add(f"/users/{oid(13)}", {"id": oid(13)})


def grants_by_principal(export: entra.Export) -> dict[str, dict[str, Any]]:
    return {g["principal_id"]: g for g in kinds(export, "grant")}


def test_direct_and_nested_members_with_via_chains_and_a_cycle(
    client: GraphClient, fake: FakeGraph
) -> None:
    nested_tenant(fake)
    export = run(client, entra.Scope(groups=(oid(1),)))
    grants = grants_by_principal(export)
    assert grants[oid(11)]["via"] == []
    assert grants[oid(2)]["via"] == []
    assert grants[oid(12)]["via"] == ["Tier0 Admins", "Server Ops"]
    assert grants[oid(3)]["via"] == ["Tier0 Admins", "Server Ops"]
    assert grants[oid(13)]["via"] == ["Tier0 Admins", "Server Ops", "Deep"]
    assert all(g["entitlement"] == "member" and g["resource_id"] == oid(1) for g in grants.values())
    assert all(g["extra"] == {} for g in grants.values())
    assert oid(1) not in grants  # the cycle back to the group is not a member of itself
    [resource] = kinds(export, "resource")
    assert resource == {
        "id": oid(1),
        "name": "Tier0 Admins",
        "kind": "group",
        "owner_ids": [oid(11)],
        "complete": True,
        "extra": {"security_enabled": "true"},
    }
    assert not kinds(export, "gap") or all("manager" in g["what"] for g in kinds(export, "gap"))


def test_principals_kinds_guests_and_managers(client: GraphClient, fake: FakeGraph) -> None:
    nested_tenant(fake)
    export = run(client, entra.Scope(groups=(oid(1),)))
    principals = {p["id"]: p for p in kinds(export, "principal")}
    assert principals[oid(13)]["extra"] == {"user_type": "Guest"}
    assert principals[oid(11)]["extra"] == {}
    assert principals[oid(2)]["kind"] == "group"
    assert principals[oid(11)] == {
        "id": oid(11),
        "name": "Avery Example",
        "kind": "user",
        "enabled": True,
        "email": "avery11@corp.example",
        "upn": "avery11@corp.example",
        "manager_id": oid(20),
        "last_sign_in": "",
        "extra": {},
    }
    assert principals[oid(20)]["name"] == "Morgan Example"
    assert principals[oid(20)]["manager_id"] == ""
    assert principals[oid(12)]["manager_id"] == ""
    assert principals[oid(13)]["manager_id"] == ""
    gaps = kinds(export, "gap")
    assert len(gaps) == 1
    assert gaps[0]["what"] == f"manager of user Jordan Example ({oid(12)})"
    assert "HTTP 500" in gaps[0]["reason"]
    manager_query = fake.queries(f"/users/{oid(11)}")[0]
    assert manager_query["$expand"][0].startswith("manager($select=id,")


def test_every_odata_type_maps_to_a_kind(client: GraphClient, fake: FakeGraph) -> None:
    items: list[dict[str, Any]] = [
        {"@odata.type": "#microsoft.graph.user", "id": "u"},
        {"@odata.type": "#microsoft.graph.servicePrincipal", "id": "s"},
        {"@odata.type": "#microsoft.graph.group", "id": "g"},
        {"@odata.type": "#microsoft.graph.device", "id": "d"},
        {"@odata.type": "#microsoft.graph.orgContact", "id": "o"},
        {"@odata.type": "#microsoft.graph.somethingNew", "id": "n"},
        {"id": "m"},
        {"@odata.type": 5, "id": "p", "accountEnabled": "yes", "displayName": 5},
        {"displayName": "no id"},
    ]
    fake.add(f"/groups/{oid(1)}", group(1, "G"))
    fake.add(f"/groups/{oid(1)}/owners", value())
    fake.add(f"/groups/{oid(1)}/members", value(*items))
    fake.add(f"/groups/{oid(1)}/transitiveMembers", value(*items))
    fake.add("/groups/g/members", value())
    export = run(client, entra.Scope(groups=(oid(1),)))
    found = {p["id"]: (p["kind"], p["enabled"], p["name"]) for p in kinds(export, "principal")}
    assert {i: k for i, (k, _, _) in found.items()} == {
        "u": "user",
        "s": "service",
        "g": "group",
        "d": "device",
        "o": "other",
        "n": "unknown",
        "m": "unknown",
        "p": "unknown",
    }
    assert found["p"][1:] == (None, "")


def test_a_principal_seen_twice_keeps_what_each_sighting_knew(
    client: GraphClient, fake: FakeGraph
) -> None:
    sparse = {"id": oid(11)}
    full = user(11, "Avery Example", userType="Guest")
    fake.add(f"/groups/{oid(1)}", group(1, "G"))
    fake.add(f"/groups/{oid(1)}/owners", value(sparse))
    fake.add(f"/groups/{oid(1)}/members", value(full))
    fake.add(f"/groups/{oid(1)}/transitiveMembers", value(full))
    export = run(client, entra.Scope(groups=(oid(1),)))
    [principal] = [p for p in kinds(export, "principal") if p["id"] == oid(11)]
    assert principal["name"] == "Avery Example"
    assert principal["kind"] == "user"
    assert principal["enabled"] is True
    assert principal["extra"] == {"user_type": "Guest"}
    # and the other order: a full sighting first is not blanked by a sparse one
    fake.add(f"/groups/{oid(2)}", group(2, "H"))
    fake.add(f"/groups/{oid(2)}/owners", value(full))
    fake.add(f"/groups/{oid(2)}/members", value(sparse))
    fake.add(f"/groups/{oid(2)}/transitiveMembers", value(sparse))
    export = run(client, entra.Scope(groups=(oid(2),)))
    [principal] = [p for p in kinds(export, "principal") if p["id"] == oid(11)]
    assert principal["name"] == "Avery Example"
    assert principal["extra"] == {"user_type": "Guest"}


def simple_group(fake: FakeGraph, n: int, name: str, members: list[dict[str, Any]]) -> None:
    fake.add(f"/groups/{oid(n)}", group(n, name))
    fake.add(f"/groups/{oid(n)}/owners", value())
    fake.add(f"/groups/{oid(n)}/members", value(*members))
    fake.add(f"/groups/{oid(n)}/transitiveMembers", value(*members))


def test_a_group_found_by_name(client: GraphClient, fake: FakeGraph) -> None:
    simple_group(fake, 1, "O'Brien Admins", [user(11, "Avery Example")])
    fake.add("/groups", value(group(1, "O'Brien Admins")))
    export = run(client, entra.Scope(groups=("O'Brien Admins",)))
    [query] = fake.queries("/groups")
    assert query["$filter"] == ["displayName eq 'O''Brien Admins'"]
    assert query["$select"] == ["id,displayName,securityEnabled"]
    assert "O%27%27Brien%20Admins" in fake.requests[0].url
    assert len(kinds(export, "grant")) == 1
    assert kinds(export, "resource")[0]["extra"] == {}


def test_a_name_with_no_match_or_two_matches_is_a_gap(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/groups", value())
    export = run(client, entra.Scope(groups=("Nobody",)))
    assert kinds(export, "gap") == [
        {"what": "group Nobody", "reason": "no group has this display name"}
    ]
    assert not kinds(export, "resource")
    fake.add("/groups", value(group(2, "Twin"), group(1, "Twin"), {"displayName": "no id"}))
    export = run(client, entra.Scope(groups=("Twin",)))
    [gap] = kinds(export, "gap")
    assert gap["reason"] == f"2 groups have this display name ({oid(1)}, {oid(2)}); use an id"
    assert not kinds(export, "resource")


def test_a_failed_name_lookup_is_a_gap(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/groups", Reply(403))
    export = run(client, entra.Scope(groups=("Some Group",)))
    [gap] = kinds(export, "gap")
    assert gap["what"] == "group Some Group"
    assert "GroupMember.Read.All" in gap["reason"]


def test_a_group_id_that_is_missing_or_denied_is_a_gap(
    client: GraphClient, fake: FakeGraph
) -> None:
    fake.add(f"/groups/{oid(1)}", Reply(404))
    fake.add(f"/groups/{oid(2)}", Reply(403))
    fake.add(f"/groups/{oid(3)}", {"displayName": "no id"})
    export = run(client, entra.Scope(groups=(oid(1), oid(2), oid(3))))
    gaps = {g["what"]: g["reason"] for g in kinds(export, "gap")}
    assert "not found" in gaps[f"group {oid(1)}"]
    assert "GroupMember.Read.All" in gaps[f"group {oid(2)}"]
    assert gaps[f"group {oid(3)}"] == "the response holds no group id"
    assert not kinds(export, "resource")


def test_all_security_groups_and_duplicates_are_read_once(
    client: GraphClient, fake: FakeGraph
) -> None:
    simple_group(fake, 1, "Alpha", [user(11, "Avery Example")])
    simple_group(fake, 2, "Beta", [])
    fake.add("/groups", value(group(2, "Beta"), group(1, "Alpha"), {"displayName": "no id"}))
    export = run(client, entra.Scope(groups=(oid(1).upper(), "Alpha"), all_security_groups=True))
    assert [r["name"] for r in kinds(export, "resource")] == ["Alpha", "Beta"]
    assert fake.paths().count(f"/groups/{oid(2)}/members") == 1
    assert kinds(export, "resource")[0]["complete"] is True


def test_all_security_groups_failing_is_a_gap(client: GraphClient, fake: FakeGraph) -> None:
    fake.add("/groups", Reply(403))
    export = run(client, entra.Scope(all_security_groups=True))
    [gap] = kinds(export, "gap")
    assert gap["what"] == "security groups"
    assert "GroupMember.Read.All" in gap["reason"]
    assert fake.queries("/groups")[0]["$filter"] == ["securityEnabled eq true"]


def test_a_failed_member_listing_marks_the_group_incomplete(
    client: GraphClient, fake: FakeGraph
) -> None:
    avery = user(11, "Avery Example")
    fake.add(f"/groups/{oid(1)}", group(1, "G"))
    fake.add(f"/groups/{oid(1)}/owners", value())
    fake.add(f"/groups/{oid(1)}/members", value(avery))
    link = f"https://graph.microsoft.com/v1.0/groups/{oid(1)}/transitiveMembers?p=2"
    fake.add(
        f"/groups/{oid(1)}/transitiveMembers",
        value(avery, **{"@odata.nextLink": link}),
        Reply(429, {}, {"Retry-After": "1"}),
    )
    export = run(client, entra.Scope(groups=(oid(1),)))
    assert kinds(export, "resource")[0]["complete"] is False
    assert len(kinds(export, "grant")) == 1
    assert any(g["what"].startswith("members of group G") for g in kinds(export, "gap"))


def test_unreadable_direct_members_leave_the_path_unknown_and_the_group_incomplete(
    client: GraphClient, fake: FakeGraph
) -> None:
    fake.add(f"/groups/{oid(1)}", group(1, "G"))
    fake.add(f"/groups/{oid(1)}/owners", Reply(403))
    fake.add(f"/groups/{oid(1)}/members", Reply(500))
    fake.add(f"/groups/{oid(1)}/transitiveMembers", value(user(11, "Avery Example")))
    export = run(client, entra.Scope(groups=(oid(1),)))
    [grant] = kinds(export, "grant")
    assert grant["via"] == ["G"]
    assert "path_unknown" in grant["extra"]
    resource = kinds(export, "resource")[0]
    assert resource["complete"] is False
    assert resource["owner_ids"] == []
    labels = sorted(g["what"] for g in kinds(export, "gap"))
    assert labels == [
        f"direct members of group G ({oid(1)})",
        f"owners of group G ({oid(1)})",
    ]


def test_a_nested_group_that_cannot_be_read_leaves_its_members_path_unknown(
    client: GraphClient, fake: FakeGraph
) -> None:
    ops = group(2, "Server Ops")
    jordan = user(12, "Jordan Example")
    fake.add(f"/groups/{oid(1)}", group(1, "G"))
    fake.add(f"/groups/{oid(1)}/owners", value())
    fake.add(f"/groups/{oid(1)}/members", value(ops))
    fake.add(f"/groups/{oid(1)}/transitiveMembers", value(ops, jordan))
    fake.add(f"/groups/{oid(2)}/members", Reply(403))
    export = run(client, entra.Scope(groups=(oid(1),)))
    grants = grants_by_principal(export)
    assert grants[oid(2)]["via"] == []
    assert grants[oid(12)]["via"] == ["G"]
    assert "path_unknown" in grants[oid(12)]["extra"]
    [gap] = kinds(export, "gap")
    assert gap["what"] == f"direct members of group Server Ops ({oid(2)})"


def test_nesting_depth_is_bounded(
    client: GraphClient, fake: FakeGraph, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(entra, "MAX_NESTED_GROUPS", 2)
    fake.add(f"/groups/{oid(1)}", group(1, "G1"))
    fake.add(f"/groups/{oid(1)}/owners", value())
    fake.add(f"/groups/{oid(1)}/members", value(group(2, "G2")))
    fake.add(f"/groups/{oid(1)}/transitiveMembers", value(group(2, "G2"), group(3, "G3")))
    fake.add(f"/groups/{oid(2)}/members", value(group(3, "G3"), {"displayName": "no id"}))
    fake.add(f"/groups/{oid(3)}/members", value(group(4, "G4")))
    fake.add(f"/groups/{oid(4)}/members", value(user(11, "Avery Example")))
    export = run(client, entra.Scope(groups=(oid(1),)))
    grants = grants_by_principal(export)
    assert grants[oid(3)]["via"] == ["G1", "G2"]
    [gap] = [g for g in kinds(export, "gap") if g["what"].startswith("nested groups")]
    assert gap["reason"] == "stopped after expanding 2 nested groups"
    assert f"/groups/{oid(4)}/members" not in fake.paths()


# --- collection: roles and PIM ------------------------------------------------------

ROLE_ADMIN = "11111111-1111-4111-8111-111111111111"
ROLE_READER = "22222222-2222-4222-8222-222222222222"


def role_tenant(fake: FakeGraph) -> None:
    fake.add(
        "/roleManagement/directory/roleDefinitions",
        value(
            {"id": ROLE_ADMIN, "displayName": "Global Administrator"},
            {"id": ROLE_READER, "displayName": "Global Reader"},
            {"id": "", "displayName": "blank id"},
            {"id": "33333333-3333-4333-8333-333333333333"},
        ),
    )
    avery = user(11, "Avery Example")
    app = {"@odata.type": "#microsoft.graph.servicePrincipal", "id": oid(30), "displayName": "App"}
    team = group(31, "Role Team")
    fake.add(
        "/roleManagement/directory/roleAssignments",
        value(
            {
                "principalId": oid(11),
                "roleDefinitionId": ROLE_ADMIN,
                "directoryScopeId": "/",
                "principal": avery,
            },
            {
                "principalId": oid(11),
                "roleDefinitionId": ROLE_ADMIN,
                "directoryScopeId": f"/administrativeUnits/{oid(40)}",
                "principal": avery,
            },
            {"principalId": oid(30), "roleDefinitionId": ROLE_READER, "principal": app},
            {"principalId": oid(31), "roleDefinitionId": ROLE_READER, "principal": team},
            {"principalId": oid(32), "roleDefinitionId": "unnamed-role", "principal": None},
            {"principalId": "", "roleDefinitionId": ROLE_READER},
            {"roleDefinitionId": ROLE_READER},
        ),
    )
    fake.add(
        "/roleManagement/directory/roleEligibilitySchedules",
        value(
            {
                "principalId": oid(11),
                "roleDefinitionId": ROLE_ADMIN,
                "directoryScopeId": "/",
                "principal": avery,
            },
        ),
    )


def test_directory_roles(client: GraphClient, fake: FakeGraph) -> None:
    role_tenant(fake)
    export = run(client, entra.Scope(roles=True))
    grants = kinds(export, "grant")
    by_key = {(g["principal_id"], g["entitlement"]): g for g in grants}
    admin = by_key[(oid(11), "Global Administrator")]
    assert admin["resource_id"] == ROLE_ADMIN
    assert admin["via"] == []
    assert admin["extra"] == {"directory_scope": f"/; /administrativeUnits/{oid(40)}"}
    assert by_key[(oid(30), "Global Reader")]["extra"] == {}
    assert by_key[(oid(32), "unnamed-role")]["resource_id"] == "unnamed-role"
    assert len(grants) == 4
    assert not any(e.endswith("(eligible)") for _, e in by_key)
    roles = {r["id"]: r for r in kinds(export, "resource")}
    assert roles[ROLE_ADMIN] == {
        "id": ROLE_ADMIN,
        "name": "Global Administrator",
        "kind": "role",
        "owner_ids": [],
        "complete": True,
        "extra": {"assignment": "active", "role_id": ROLE_ADMIN},
    }
    assert roles["33333333-3333-4333-8333-333333333333"]["name"] == (
        "33333333-3333-4333-8333-333333333333"
    )
    assert roles["unnamed-role"]["name"] == "unnamed-role"
    principals = {p["id"]: p for p in kinds(export, "principal")}
    assert principals[oid(30)]["kind"] == "service"
    assert principals[oid(32)]["kind"] == "unknown"
    gaps = {g["what"]: g["reason"] for g in kinds(export, "gap")}
    assert gaps["role assignments"] == "2 assignments without a principal or role id were skipped"
    [holder] = [w for w in gaps if w.startswith("members of group Role Team")]
    assert "--group" in gaps[holder]
    assert "/roleManagement/directory/roleEligibilitySchedules" not in fake.paths()
    assert "$expand" in fake.queries("/roleManagement/directory/roleAssignments")[0]
    assert "$top" not in fake.queries("/roleManagement/directory/roleAssignments")[0]


def test_pim_eligible_assignments_are_marked_eligible(client: GraphClient, fake: FakeGraph) -> None:
    role_tenant(fake)
    export = run(client, entra.Scope(pim=True))
    [grant] = kinds(export, "grant")
    assert grant["entitlement"] == "Global Administrator (eligible)"
    assert grant["resource_id"] == f"{ROLE_ADMIN}:eligible"
    assert "/roleManagement/directory/roleAssignments" not in fake.paths()
    roles = {r["id"]: r for r in kinds(export, "resource")}
    assert ROLE_ADMIN not in roles  # active assignments were not read
    assert roles[f"{ROLE_ADMIN}:eligible"]["name"] == "Global Administrator (eligible)"


def test_roles_and_pim_are_separate_resources_each_with_its_own_completeness(
    client: GraphClient, fake: FakeGraph
) -> None:
    role_tenant(fake)
    export = run(client, entra.Scope(roles=True, pim=True))
    mine = [g for g in kinds(export, "grant") if g["principal_id"] == oid(11)]
    assert sorted(g["entitlement"] for g in mine) == [
        "Global Administrator",
        "Global Administrator (eligible)",
    ]
    resources = {r["id"]: r for r in kinds(export, "resource")}
    assert set(resources) >= {ROLE_ADMIN, ROLE_READER, f"{ROLE_ADMIN}:eligible"}
    assert {g["resource_id"] for g in mine} == {ROLE_ADMIN, f"{ROLE_ADMIN}:eligible"}


def test_role_failures_are_gaps_and_make_roles_incomplete(
    client: GraphClient, fake: FakeGraph
) -> None:
    fake.add("/roleManagement/directory/roleDefinitions", Reply(403))
    fake.add("/roleManagement/directory/roleAssignments", Reply(403))
    fake.add(
        "/roleManagement/directory/roleEligibilitySchedules",
        {
            "value": [{"principalId": oid(11), "roleDefinitionId": ROLE_ADMIN}],
            "@odata.nextLink": "https://evil.example/v1.0/next",
        },
    )
    export = run(client, entra.Scope(roles=True, pim=True))
    gaps = {g["what"]: g["reason"] for g in kinds(export, "gap")}
    assert "RoleManagement.Read.Directory" in gaps["role names"]
    assert "RoleManagement.Read.Directory" in gaps["active directory role assignments"]
    assert "does not stay on the Graph host" in gaps["eligible directory role assignments"]
    [grant] = kinds(export, "grant")
    assert grant["entitlement"] == f"{ROLE_ADMIN} (eligible)"
    [role] = kinds(export, "resource")
    assert role["complete"] is False
    assert role["name"] == f"{ROLE_ADMIN} (eligible)"


# --- collection: managers -----------------------------------------------------------


def test_manager_lookups_stop_after_too_many_failures(
    client: GraphClient, fake: FakeGraph, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(entra, "MAX_MANAGER_FAILURES", 2)
    members = [user(n, "Avery Example") for n in range(11, 16)]
    simple_group(fake, 1, "G", members)
    for n in range(11, 16):
        fake.add(f"/users/{oid(n)}", Reply(403))
    export = run(client, entra.Scope(groups=(oid(1),)))
    labels = [g["what"] for g in kinds(export, "gap")]
    assert labels.count("managers") == 1
    assert len(labels) == 3
    assert len([p for p in fake.paths() if p.startswith("/users/")]) == 2


def test_manager_lookups_are_bounded_in_number(
    client: GraphClient, fake: FakeGraph, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(entra, "MAX_MANAGER_LOOKUPS", 1)
    simple_group(fake, 1, "G", [user(11, "Avery Example"), user(12, "Jordan Example")])
    export = run(client, entra.Scope(groups=(oid(1),)))
    [gap] = kinds(export, "gap")
    assert gap["reason"].startswith("managers of the last 1 users were not read")
    assert len([p for p in fake.paths() if p.startswith("/users/")]) == 1


def test_only_users_get_a_manager_lookup_and_a_bad_manager_is_ignored(
    client: GraphClient, fake: FakeGraph
) -> None:
    simple_group(fake, 1, "G", [user(11, "Avery Example"), group(2, "Server Ops")])
    fake.add("/groups/" + oid(2) + "/members", value())
    fake.add(f"/users/{oid(11)}", {"id": oid(11), "manager": "not an object"})
    export = run(client, entra.Scope(groups=(oid(1),)))
    assert [p for p in fake.paths() if p.startswith("/users/")] == [f"/users/{oid(11)}"]
    assert {p["manager_id"] for p in kinds(export, "principal")} == {""}


# --- the export ---------------------------------------------------------------------


def test_the_export_has_a_header_records_and_a_trailer_that_checks(
    client: GraphClient, fake: FakeGraph
) -> None:
    nested_tenant(fake)
    export = run(client, entra.Scope(groups=(oid(1), "x"), roles=False))
    data = entra.render(export)
    lines = data.split(b"\n")
    assert lines[-1] == b""
    records = read_export(data)
    header, trailer = records[0], records[-1]
    assert header == {
        "shaar_export": 1,
        "system": "entra",
        "collector": {"name": "shaar collect entra", "version": __version__},
        "collected_at": "2026-11-12T09:30:00Z",
        "scope": {
            "cloud": "global",
            "graph_host": "graph.microsoft.com",
            "groups": sorted([oid(1), "x"]),
            "all_security_groups": False,
            "roles": False,
            "pim": False,
        },
        "tenant": TENANT,
    }
    assert set(trailer) == {"end", "records", "sha256"}
    assert trailer["end"] is True
    assert trailer["records"] == len(records) - 2
    before = data[: data.rindex(b'{"end"')]
    assert trailer["sha256"] == hashlib.sha256(before).hexdigest()
    assert all(len(line) < 1024 * 1024 for line in lines)
    assert b"\r" not in data
    assert TOKEN.encode() not in data


def test_record_order_is_sorted_and_does_not_depend_on_collection_order(
    client: GraphClient, fake: FakeGraph
) -> None:
    members = [user(13, "Casey Example"), user(11, "Avery Example"), user(12, "Jordan Example")]
    simple_group(fake, 1, "G", members)
    first = entra.render(run(client, entra.Scope(groups=(oid(1),))))
    simple_group(fake, 1, "G", list(reversed(members)))
    second = entra.render(run(client, entra.Scope(groups=(oid(1),))))
    assert first == second
    order = [r["principal"]["id"] for r in read_export(first) if "principal" in r]
    assert order == sorted(order)
    kinds_in_order = [next(iter(r)) for r in read_export(first)[1:-1]]
    assert kinds_in_order == sorted(
        kinds_in_order, key=["principal", "resource", "grant", "gap"].index
    )


def test_non_ascii_text_is_written_as_utf8() -> None:
    export = entra.Export(TENANT, CLOUDS["global"], entra.Scope(roles=True), "2026-11-12T09:30:00Z")
    export.gaps.add(("grupo Ñandú", "café"))
    data = entra.render(export)
    assert "grupo Ñandú".encode() in data


def test_collected_at(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    assert entra.collected_at(NOW) == "2026-11-12T09:30:00Z"
    assert entra.collected_at().endswith("Z")
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "86400")
    assert entra.collected_at(NOW) == "1970-01-02T00:00:00Z"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "9" * 30)
    assert entra.collected_at(NOW) == "2026-11-12T09:30:00Z"
    monkeypatch.setenv("SOURCE_DATE_EPOCH", "not a number")
    assert entra.collected_at(NOW) == "2026-11-12T09:30:00Z"


def test_the_scope_knows_when_it_is_empty() -> None:
    assert entra.Scope().empty()
    assert not entra.Scope(pim=True).empty()


# --- the output file ----------------------------------------------------------------


def test_write_private_creates_an_owner_only_file_and_refuses_to_overwrite(tmp_path: Path) -> None:
    target = tmp_path / "out.jsonl"
    fileout.write_private(target, b"one\n", force=False)
    assert target.read_bytes() == b"one\n"
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    with pytest.raises(CollectionError, match="already exists; use --force"):
        fileout.write_private(target, b"two\n", force=False)
    assert target.read_bytes() == b"one\n"
    fileout.write_private(target, b"three\n", force=True)
    assert target.read_bytes() == b"three\n"
    if os.name == "posix":
        assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert [p.name for p in tmp_path.iterdir()] == ["out.jsonl"]


@pytest.mark.skipif(os.name != "posix", reason="symbolic links need POSIX")
def test_write_private_never_writes_through_a_symlink(tmp_path: Path) -> None:
    secret_target = tmp_path / "victim"
    secret_target.write_text("keep")
    link = tmp_path / "out.jsonl"
    link.symlink_to(secret_target)
    with pytest.raises(CollectionError, match="already exists"):
        fileout.write_private(link, b"x", force=False)
    fileout.write_private(link, b"x", force=True)
    assert secret_target.read_text() == "keep"
    assert not link.is_symlink()
    assert link.read_bytes() == b"x"


def test_write_private_refuses_a_directory_and_reports_os_errors(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match="is a directory"):
        fileout.write_private(tmp_path, b"x", force=True)
    with pytest.raises(CollectionError, match="cannot write"):
        fileout.write_private(tmp_path / "missing" / "out", b"x", force=False)
    with pytest.raises(CollectionError, match="cannot write"):
        fileout.write_private(tmp_path / "missing" / "out", b"x", force=True)


def test_a_failed_write_leaves_no_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(fd: int, *_: object) -> None:
        os.close(fd)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(os, "fdopen", broken)
    with pytest.raises(CollectionError, match="cannot write"):
        fileout.write_private(tmp_path / "a", b"x", force=False)
    with pytest.raises(CollectionError, match="cannot write"):
        fileout.write_private(tmp_path / "b", b"x", force=True)
    assert list(tmp_path.iterdir()) == []


def test_a_failed_replace_removes_the_temporary_file(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(*_: object) -> Path:
        raise OSError(13, "Permission denied")

    monkeypatch.setattr(Path, "replace", broken)
    with pytest.raises(CollectionError, match="cannot write"):
        fileout.write_private(tmp_path / "a", b"x", force=True)
    assert list(tmp_path.iterdir()) == []


# --- the command --------------------------------------------------------------------


def parse(*argv: str) -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="shaar")
    commands = parser.add_subparsers(dest="command")
    collect = commands.add_parser("collect")
    entra.add_collect_entra_arguments(collect.add_subparsers(dest="source", required=True))
    return parser.parse_args(["collect", "entra", *argv])


def base(tmp_path: Path, *extra: str) -> list[str]:
    return ["--tenant", TENANT, "--client-id", CLIENT, "-o", str(tmp_path / "out.jsonl"), *extra]


@pytest.fixture
def cli_env(fake: FakeGraph, identity: FakeIdentity, monkeypatch: pytest.MonkeyPatch) -> FakeGraph:
    identity.built.clear()  # the fake azure.identity is installed by this fixture
    monkeypatch.setenv("ENTRA_TEST_SECRET", "cli-secret-VALUE-123")
    monkeypatch.setenv("ENTRA_TEST_PFX_PASSWORD", "pfx-password-VALUE-456")
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    nested_tenant(fake)
    return fake


@pytest.mark.usefixtures("cli_env")
def test_the_command_writes_an_owner_only_export_and_prints_gaps(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse(*base(tmp_path, "--client-secret", "env:ENTRA_TEST_SECRET", "--group", oid(1)))
    assert entra.run_collect_entra(args) == 0
    out = capsys.readouterr()
    assert "Read 6 principals, 1 resources and 5 grants" in out.out
    assert f"into {tmp_path / 'out.jsonl'}" in out.out
    assert "not read: manager of user Jordan Example" in out.out
    assert out.err == ""
    path = tmp_path / "out.jsonl"
    if os.name == "posix":
        assert stat.S_IMODE(path.stat().st_mode) == 0o600
    records = read_export(path.read_bytes())
    assert records[0]["system"] == "entra"
    assert records[-1]["end"] is True
    blob = path.read_bytes() + out.out.encode() + out.err.encode()
    assert b"cli-secret-VALUE-123" not in blob
    assert TOKEN.encode() not in blob


def test_the_command_uses_the_chosen_cloud_and_a_certificate_with_a_password(
    cli_env: FakeGraph, identity: FakeIdentity, tmp_path: Path
) -> None:
    pem = tmp_path / "app.pfx"
    pem.write_bytes(b"synthetic")
    cli_env.host = "dod-graph.microsoft.us"
    args = parse(
        *base(
            tmp_path,
            "--certificate",
            str(pem),
            "--certificate-password",
            "env:ENTRA_TEST_PFX_PASSWORD",
            "--cloud",
            "usgovdod",
            "--group",
            oid(1),
        )
    )
    assert entra.run_collect_entra(args) == 0
    label, _, kwargs = identity.built[0]
    assert label == "certificate"
    assert kwargs["password"] == "pfx-password-VALUE-456"  # noqa: S105
    assert kwargs["authority"] == "login.example-gov"
    assert all(r.url.startswith("https://dod-graph.microsoft.us/v1.0/") for r in cli_env.requests)


@pytest.mark.usefixtures("cli_env")
def test_the_command_with_a_device_code(identity: FakeIdentity, tmp_path: Path) -> None:
    args = parse(*base(tmp_path, "--device-code", "--group", oid(1)))
    assert entra.run_collect_entra(args) == 0
    assert identity.built[0][0] == "device"


def test_an_existing_output_needs_force_and_is_checked_before_any_request(
    cli_env: FakeGraph, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (tmp_path / "out.jsonl").write_text("old")
    args = parse(*base(tmp_path, "--device-code", "--group", oid(1)))
    assert entra.run_collect_entra(args) == 3
    assert "already exists; use --force" in capsys.readouterr().err
    assert (tmp_path / "out.jsonl").read_text() == "old"
    assert not cli_env.requests
    args = parse(*base(tmp_path, "--device-code", "--group", oid(1), "--force"))
    assert entra.run_collect_entra(args) == 0
    assert json.loads((tmp_path / "out.jsonl").read_text().split("\n")[0])["shaar_export"] == 1


def test_nothing_chosen_to_read_is_a_usage_error(
    cli_env: FakeGraph, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert entra.run_collect_entra(parse(*base(tmp_path, "--device-code"))) == 2
    assert "choose what to read" in capsys.readouterr().err
    assert not cli_env.requests


@pytest.mark.usefixtures("cli_env")
def test_a_certificate_password_without_a_certificate_is_a_usage_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse(
        *base(
            tmp_path, "--device-code", "--certificate-password", "env:ENTRA_TEST_SECRET", "--roles"
        )
    )
    assert entra.run_collect_entra(args) == 2
    assert "--certificate-password needs --certificate" in capsys.readouterr().err


def test_a_missing_certificate_or_secret_is_exit_3(
    cli_env: FakeGraph, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = parse(*base(tmp_path, "--certificate", str(tmp_path / "nope.pem"), "--roles"))
    assert entra.run_collect_entra(args) == 3
    assert "cannot be read" in capsys.readouterr().err
    args = parse(*base(tmp_path, "--client-secret", "env:ENTRA_TEST_UNSET_VARIABLE", "--roles"))
    assert entra.run_collect_entra(args) == 3
    assert "ENTRA_TEST_UNSET_VARIABLE is not set" in capsys.readouterr().err
    assert not cli_env.requests


@pytest.mark.usefixtures("fake")
def test_a_missing_extra_is_exit_3_before_any_secret_is_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setitem(sys.modules, "azure.identity", None)
    args = parse(*base(tmp_path, "--client-secret", "env:ENTRA_TEST_UNSET_VARIABLE", "--roles"))
    assert entra.run_collect_entra(args) == 3
    err = capsys.readouterr().err
    assert "pip install 'faithful-shaar[entra]'" in err
    assert "ENTRA_TEST_UNSET_VARIABLE" not in err


def test_a_rejected_token_is_exit_3_and_writes_nothing(
    cli_env: FakeGraph, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli_env.add(f"/groups/{oid(1)}", Reply(401))
    args = parse(*base(tmp_path, "--client-secret", "env:ENTRA_TEST_SECRET", "--group", oid(1)))
    assert entra.run_collect_entra(args) == 3
    err = capsys.readouterr().err
    assert "rejected the access token" in err
    assert TOKEN not in err
    assert not (tmp_path / "out.jsonl").exists()


@pytest.mark.usefixtures("cli_env")
def test_a_secret_inside_a_sign_in_error_is_redacted(
    identity: FakeIdentity, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    class Leaky(FakeCredential):
        def __init__(self, *args: Any, **kwargs: Any) -> None:
            super().__init__()

        def get_token(self, *scopes: str) -> Token:
            raise RuntimeError("AADSTS7000215 invalid secret cli-secret-VALUE-123 supplied")

    identity.ClientSecretCredential = Leaky
    args = parse(*base(tmp_path, "--client-secret", "env:ENTRA_TEST_SECRET", "--group", oid(1)))
    assert entra.run_collect_entra(args) == 3
    err = capsys.readouterr().err
    assert "AADSTS7000215" in err
    assert "cli-secret-VALUE-123" not in err
    assert secrets.REDACTED in err


@pytest.mark.usefixtures("cli_env")
def test_unwritable_output_is_exit_3(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    args = parse(
        "--tenant",
        TENANT,
        "--client-id",
        CLIENT,
        "-o",
        str(tmp_path / "missing" / "out.jsonl"),
        "--device-code",
        "--group",
        oid(1),
    )
    assert entra.run_collect_entra(args) == 3
    assert "cannot write" in capsys.readouterr().err


def test_control_characters_in_names_cannot_reach_the_terminal(
    cli_env: FakeGraph, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    cli_env.add("/groups", value())
    args = parse(*base(tmp_path, "--device-code", "--group", "Evil\x1b[2JName\r"))
    assert entra.run_collect_entra(args) == 0
    out = capsys.readouterr().out
    assert "\x1b" not in out
    assert "\r" not in out
    assert "Evil\\x1b[2JName\\r" in out


@pytest.mark.parametrize(
    "argv",
    [
        ["--tenant", "not a tenant", "--client-id", CLIENT, "-o", "x", "--device-code", "--roles"],
        ["--tenant", TENANT, "--client-id", "nope", "-o", "x", "--device-code", "--roles"],
        ["--tenant", TENANT, "--client-id", CLIENT, "-o", "x", "--roles"],
        ["--tenant", TENANT, "--client-id", CLIENT, "-o", "x", "--device-code", "--cloud", "mars"],
        [
            "--tenant",
            TENANT,
            "--client-id",
            CLIENT,
            "-o",
            "x",
            "--device-code",
            "--client-secret",
            "env:X",
            "--roles",
        ],
    ],
)
def test_bad_options_are_refused_by_the_parser(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        parse(*argv)
    assert caught.value.code == 2


def test_tenant_may_be_a_domain_and_ids_are_lowercased() -> None:
    args = parse(
        "--tenant",
        "Corp.Example",
        "--client-id",
        CLIENT.upper(),
        "-o",
        "x",
        "--device-code",
        "--roles",
        "--pim",
        "--all-security-groups",
        "--group",
        "A",
        "B",
        "--group",
        "C",
    )
    assert args.tenant == "corp.example"
    assert args.client_id == CLIENT
    assert args.group == ["A", "B", "C"]
    assert args.run is entra.run_collect_entra


def test_every_request_in_a_full_run_is_a_get(cli_env: FakeGraph, tmp_path: Path) -> None:
    role_tenant(cli_env)
    args = parse(
        *base(
            tmp_path,
            "--device-code",
            "--group",
            oid(1),
            "--roles",
            "--pim",
            "--all-security-groups",
        )
    )
    cli_env.add("/groups", value(group(1, "Tier0 Admins")))
    assert entra.run_collect_entra(args) == 0
    assert len(cli_env.requests) > 10
    assert {r.method for r in cli_env.requests} == {"GET"}
    assert Path(tmp_path / "out.jsonl").exists()


def test_a_group_nested_in_another_target_is_read_once(
    client: GraphClient, fake: FakeGraph
) -> None:
    simple_group(fake, 1, "Outer", [group(2, "Inner")])
    simple_group(fake, 2, "Inner", [user(11, "Avery Example")])
    fake.add("/groups", value(group(1, "Outer"), group(2, "Inner")))
    export = run(client, entra.Scope(all_security_groups=True))
    assert fake.paths().count(f"/groups/{oid(2)}/members") == 1
    assert {(g["resource_id"], g["principal_id"]) for g in kinds(export, "grant")} == {
        (oid(1), oid(2)),
        (oid(2), oid(11)),
    }


def test_owners_and_managers_without_an_id_are_ignored(
    client: GraphClient, fake: FakeGraph
) -> None:
    simple_group(fake, 1, "G", [user(11, "Avery Example")])
    fake.add(f"/groups/{oid(1)}/owners", value({"displayName": "Nameless"}))
    fake.add(f"/users/{oid(11)}", {"id": oid(11), "manager": {"displayName": "Nameless"}})
    export = run(client, entra.Scope(groups=(oid(1),)))
    assert kinds(export, "resource")[0]["owner_ids"] == []
    assert [p["id"] for p in kinds(export, "principal")] == [oid(11)]
    assert kinds(export, "principal")[0]["manager_id"] == ""
