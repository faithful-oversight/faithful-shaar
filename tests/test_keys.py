# SPDX-FileCopyrightText: 2026 Faithful Oversight, LLC
# SPDX-License-Identifier: Apache-2.0
"""Keys: the same thing gives the same key in every export."""

from __future__ import annotations

import pytest

from faithful_shaar import keys
from faithful_shaar.model import Source

TENANT = "00000000-0000-4000-8000-0000000000f0"


def test_keys_are_normalized() -> None:
    assert keys.sid(" s-1-5-21-1000-1000-1000-1104 ") == "ad:sid:S-1-5-21-1000-1000-1000-1104"
    assert (
        keys.dn("CN=Avery,OU=People,DC=corp,DC=example")
        == "ad:dn:cn=avery,ou=people,dc=corp,dc=example"
    )
    assert (
        keys.entra(TENANT.upper(), "00000000-0000-4000-8000-00000000000A")
        == f"entra:{TENANT}:id:00000000-0000-4000-8000-00000000000a"
    )
    assert keys.entra_role(TENANT, " ABC ") == f"entra:{TENANT}:role:abc"
    assert keys.csv("Ledger", " AVERY ") == "csv:ledger:avery"
    assert keys.grant("r", "p", " Member ") == "r|p|member"


def test_the_same_object_id_in_two_tenants_is_two_things() -> None:
    other = "11111111-1111-4111-8111-111111111111"
    oid = "00000000-0000-4000-8000-00000000000a"
    assert keys.entra(TENANT, oid) != keys.entra(other, oid)
    assert keys.entra_role(TENANT, "r") != keys.entra_role(other, "r")


def test_an_unknown_tenant_or_domain_is_marked_unscoped() -> None:
    assert keys.entra("", "x") == "entra:?:id:x"
    assert keys.entra("not-a-guid", "x") == "entra:?:id:x"
    assert keys.unscoped(keys.entra("", "x"))
    assert not keys.unscoped(keys.entra(TENANT, "x"))
    assert keys.sid("S-1-5-32-544") == "ad:sid:S-1-5-32-544@?"
    assert keys.unscoped(keys.sid("S-1-5-32-544"))
    assert keys.sid("S-1-5-32-544", "CORP.example") == "ad:sid:S-1-5-32-544@corp.example"
    assert keys.sid("S-1-5-32-544", "a.example") != keys.sid("S-1-5-32-544", "b.example")
    assert not keys.unscoped(keys.sid("S-1-5-21-1-2-3-500"))


def test_a_separator_inside_a_part_cannot_make_two_grants_one() -> None:
    first = keys.grant("csv:app:a|b", "c", "d")
    second = keys.grant("csv:app:a", "b|c", "d")
    assert first != second
    assert keys.grant("r", "p", "100%|x") == "r|p|100%25%7Cx"
    assert keys.entitlement_of(keys.grant("r|s", "p", "Owner")) == "owner"


@pytest.mark.parametrize("value", ["", "S-1", "1-5-21", "S-1-5-x"])
def test_a_sid_must_look_like_one(value: str) -> None:
    with pytest.raises(ValueError, match="is not a SID"):
        keys.sid(value)


@pytest.mark.parametrize(
    ("value", "match"),
    [
        ("", "is not a system"),
        ("bad name", "is not a system"),
        ("-x", "is not a system"),
        ("AD", "reserved"),
        ("entra", "reserved"),
    ],
)
def test_system_names(value: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        keys.system_name(value)


def test_system_of() -> None:
    assert keys.system_of("ad:sid:S-1-5-32-544") == "ad"
    assert keys.system_of("entra:role:abc") == "entra"
    assert keys.system_of("csv:ledger:avery") == "csv:ledger"
    assert (
        keys.system_of(keys.grant("csv:ledger:app", "csv:ledger:avery", "reader")) == "csv:ledger"
    )


def test_a_source_reads_as_text() -> None:
    assert str(Source("ad.jsonl")) == "ad.jsonl"
    assert str(Source("ad.jsonl", "line 4")) == "ad.jsonl, line 4"
