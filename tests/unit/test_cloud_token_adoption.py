"""Cloud key tokens can adopt a REAL decoy identity, which is what makes them observable.

A generated AKIA... string is not a key AWS issued, so using it leaves no CloudTrail event for
the forwarder to relay: the token was bait that could never fire. A decoy IAM user / service
principal / service account the operator creates (examples/cloud-forwarders/*/decoy_*) is a
principal the cloud logs, and these tests pin that the token adopts it verbatim, rejects
malformed input rather than creating a token that can never fire, and then matches the audit-log
event the cloud emits for it.
"""

import json
import os

import pytest

os.environ["DATABASE_URL"] = os.environ.get("TEST_DATABASE_URL", "sqlite+aiosqlite:///:memory:")

pytestmark = pytest.mark.asyncio

REAL_AWS = {
    "access_key_id": "AKIAIOSFODNN7EXAMPLE",
    "secret_access_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
}
TENANT = "11111111-2222-3333-4444-555555555555"
APP = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"


@pytest.fixture(autouse=True)
async def setup_db():
    from honeypot_mcp import token_matchers
    from honeypot_mcp.storage import event_buffer
    from honeypot_mcp.storage.database import close_db, init_db

    event_buffer.reset_for_tests()
    token_matchers.invalidate_cache()
    await init_db()
    yield
    token_matchers.invalidate_cache()
    event_buffer.reset_for_tests()
    await close_db()


def _gcp_key(email="svc-backup-prod@proj.iam.gserviceaccount.com"):
    return {
        "type": "service_account", "project_id": "proj", "private_key_id": "ab" * 20,
        "private_key": "-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----\n",
        "client_email": email, "client_id": "123456789012345678901",
    }  # fmt: skip


async def test_an_aws_key_from_the_account_is_adopted_verbatim_and_a_generated_one_is_marked():
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_aws

    adopted = await honeytoken_generate_aws("decoy", **REAL_AWS)
    assert adopted["token_value"] == f"{REAL_AWS['access_key_id']}:{REAL_AWS['secret_access_key']}"
    generated = await honeytoken_generate_aws("lookalike")
    assert generated["token_value"].split(":")[0] != REAL_AWS["access_key_id"]

    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken, HoneytokenType
    from honeypot_mcp.tokens import get_provider

    provider = get_provider(HoneytokenType.API_KEY)
    async with get_session() as session:
        adopted_row = await session.get(Honeytoken, adopted["id"])
        generated_row = await session.get(Honeytoken, generated["id"])
        adopted_text = provider.plant_instructions(adopted_row.token_value, adopted_row.token_meta)
        generated_text = provider.plant_instructions(
            generated_row.token_value, generated_row.token_meta
        )
    assert "REAL key" in adopted_text
    assert "does not exist in AWS" in generated_text


@pytest.mark.parametrize(
    "bad",
    [
        {"access_key_id": "AKIAIOSFODNN7EXAMPLE"},  # secret missing
        {"access_key_id": "nope", "secret_access_key": REAL_AWS["secret_access_key"]},
        {"access_key_id": "AKIAIOSFODNN7EXAMPLE", "secret_access_key": "short"},
    ],
)
async def test_a_malformed_aws_key_is_refused_not_turned_into_a_token_that_can_never_fire(bad):
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_aws, honeytoken_list

    out = await honeytoken_generate_aws("typo", **bad)
    assert "error" in out
    assert (await honeytoken_list()) == [] or all(
        t["label"] != "typo" for t in await honeytoken_list()
    )


async def test_the_audit_log_event_for_the_decoy_key_triggers_its_token():
    """The point of adoption: CloudTrail's record of the (denied) call names the key."""
    from honeypot_mcp.token_matchers import match_cloud_event
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_aws

    created = await honeytoken_generate_aws("decoy", **REAL_AWS)
    cloudtrail = {
        "eventName": "ListBuckets", "errorCode": "AccessDenied", "sourceIPAddress": "203.0.113.9",
        "userIdentity": {"type": "IAMUser", "accessKeyId": REAL_AWS["access_key_id"]},
    }  # fmt: skip
    assert await match_cloud_event(cloudtrail) == (created["id"], "aws")


async def test_azure_service_principal_is_adopted_and_validated():
    from honeypot_mcp.token_matchers import match_cloud_event
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    out = await honeytoken_create(
        "azure_credential", "decoy",
        {"client_id": APP, "client_secret": "s3cret~value", "tenant_id": TENANT},
    )  # fmt: skip
    assert f"AZURE_CLIENT_ID={APP}" in out["token_value"] and TENANT in out["token_value"]
    assert await match_cloud_event({"appId": APP}) == (out["id"], "azure")

    for bad in (
        {"client_id": "not-a-guid", "client_secret": "x", "tenant_id": TENANT},
        {"client_id": APP, "client_secret": "x"},  # tenant missing
    ):
        assert "error" in await honeytoken_create("azure_credential", "bad", bad)


async def test_gcp_service_account_key_is_adopted_and_validated():
    from honeypot_mcp.token_matchers import match_cloud_event
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    key = _gcp_key()
    out = await honeytoken_create(
        "gcp_service_account", "decoy", {"service_account_json": json.dumps(key)}
    )
    assert json.loads(out["token_value"])["client_email"] == key["client_email"]
    event = {
        "protoPayload": {"authenticationInfo": {"principalEmail": key["client_email"].upper()}}
    }
    assert await match_cloud_event(event) == (out["id"], "gcp")

    for bad in (
        "{not json",
        json.dumps({**key, "type": "user"}),
        json.dumps({"type": "service_account"}),
    ):
        assert "error" in await honeytoken_create(
            "gcp_service_account", "bad", {"service_account_json": bad}
        )


# ── hardening found in review ────────────────────────────────────────────────


async def test_a_trailing_newline_cannot_slip_past_the_format_checks():
    """`re.match` with `$` accepts "...\\n", storing a token that no real event can ever match."""
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_generate_aws

    out = await honeytoken_generate_aws(
        "nl",
        access_key_id=REAL_AWS["access_key_id"] + "\n",
        secret_access_key=REAL_AWS["secret_access_key"],
    )
    assert "error" in out
    out = await honeytoken_create(
        "azure_credential",
        "nl",
        {"client_id": APP + "\n", "client_secret": "x", "tenant_id": TENANT},
    )
    assert "error" in out


async def test_an_azure_secret_cannot_forge_lines_in_the_env_block():
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    for secret in ("a\nAZURE_TENANT_ID=evil", "has space", "", "x" * 300, 12345):
        out = await honeytoken_create(
            "azure_credential",
            "forge",
            {"client_id": APP, "client_secret": secret, "tenant_id": TENANT},
        )
        assert "error" in out, secret


async def test_a_malformed_gcp_key_is_refused_and_a_huge_or_deep_one_does_not_crash():
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    key = _gcp_key()
    bad = [
        {**key, "client_email": 42},
        {**key, "private_key_id": ["a"]},
        {**key, "private_key": "hello"},
        {**key, "client_email": "not-an-email"},
        "[" * 100_000,  # recursion bomb
        "x" * 5_000_000,  # far larger than any key file
    ]
    for candidate in bad:
        payload = candidate if isinstance(candidate, str) else json.dumps(candidate)
        out = await honeytoken_create(
            "gcp_service_account", "bad", {"service_account_json": payload}
        )
        assert "error" in out, str(candidate)[:40]


async def test_registering_the_same_identity_twice_is_refused_without_echoing_the_secret():
    """A second registration used to hit a unique-constraint error whose message quoted the
    bound parameters, i.e. the plaintext secret."""
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_aws

    await honeytoken_generate_aws("first", **REAL_AWS)
    again = await honeytoken_generate_aws("second", **REAL_AWS)
    assert "already registered" in again["error"]
    assert REAL_AWS["secret_access_key"] not in json.dumps(again)


async def test_one_identifier_cannot_shadow_another_across_clouds():
    """The cloud index is a single map: a GCP private_key_id equal to an AWS key id would
    take over that entry."""
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_generate_aws

    await honeytoken_generate_aws("aws", **REAL_AWS)
    hijack = _gcp_key()
    hijack["private_key_id"] = REAL_AWS["access_key_id"]
    out = await honeytoken_create(
        "gcp_service_account", "hijack", {"service_account_json": json.dumps(hijack)}
    )
    assert "already registered" in out["error"]


async def test_the_key_file_is_not_stored_a_second_time():
    from honeypot_mcp.storage.database import get_session
    from honeypot_mcp.storage.models import Honeytoken
    from honeypot_mcp.tools.honeytoken import honeytoken_create

    out = await honeytoken_create(
        "gcp_service_account", "k", {"service_account_json": json.dumps(_gcp_key())}
    )
    assert "service_account_json" not in json.dumps(out.get("metadata", {}))
    async with get_session() as session:
        row = await session.get(Honeytoken, out["id"])
        assert "service_account_json" not in row.token_meta
        assert "private_key" not in row.token_meta


async def test_an_adopted_token_cannot_be_rotated_into_a_generated_one():
    """Rotation regenerates the secret. For an adopted token that silently swapped a real
    decoy for a lookalike that exists nowhere, so detection would stop without a sign."""
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_aws, honeytoken_rotate

    adopted = await honeytoken_generate_aws("real", **REAL_AWS)
    out = await honeytoken_rotate(adopted["id"])
    assert "cloud account" in out["error"]


async def test_a_generated_azure_token_still_rotates():
    from honeypot_mcp.tools.honeytoken import honeytoken_create, honeytoken_rotate

    generated = await honeytoken_create("azure_credential", "gen")
    rotated = await honeytoken_rotate(generated["id"])
    assert "error" not in rotated, rotated


async def test_a_forwarded_event_with_oddly_shaped_fields_does_not_crash_the_matcher():
    from honeypot_mcp.token_matchers import match_cloud_event
    from honeypot_mcp.tools.honeytoken import honeytoken_generate_aws

    await honeytoken_generate_aws("real", **REAL_AWS)
    for odd in (
        {"userIdentity": "root"}, {"claims": "x"}, {"identity": {"claims": "x"}},
        {"protoPayload": "x"}, {"protoPayload": {"authenticationInfo": []}},
        {"authenticationInfo": "x"},
    ):  # fmt: skip
        assert await match_cloud_event(odd) == (None, None)


async def test_the_forwarders_report_what_a_deny_all_decoy_actually_does():
    """IAM cannot deny sts:GetCallerIdentity, so a decoy user's first call succeeds with no
    errorCode; the AWS filter must forward it. Azure service-principal sign-ins are their own
    log category."""
    import importlib.util
    import pathlib

    root = pathlib.Path(__file__).resolve().parents[2] / "examples" / "cloud-forwarders"
    aws = importlib.util.spec_from_file_location("aws_fwd", root / "aws" / "lambda_function.py")
    module = importlib.util.module_from_spec(aws)
    aws.loader.exec_module(module)
    assert module._is_interesting({"eventName": "GetCallerIdentity"})
