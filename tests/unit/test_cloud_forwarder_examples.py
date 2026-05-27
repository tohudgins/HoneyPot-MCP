"""Smoke tests for the cloud forwarder examples.

The forwarders in `examples/cloud-forwarders/` aren't part of the package
(they get deployed standalone in customer environments). This test loads
each forwarder module from its file path, recomputes the HMAC signature
the forwarder would produce, and asserts that the canary `/cloud-event`
receiver would accept it. That way, any drift between the forwarders'
signing logic and the receiver's verification breaks CI.

We don't actually invoke the Lambda/Function entry points (they expect
runtime-specific event envelopes). We test the signing primitives the
entry points share.
"""

from __future__ import annotations

import hashlib
import hmac
import importlib.util
import os
import sys
import types
from pathlib import Path

import pytest

os.environ["DATABASE_URL"] = "sqlite+aiosqlite:///:memory:"

_EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "cloud-forwarders"
_TEST_SECRET = "shared-secret-for-tests"
_TEST_PAYLOAD = b'{"eventName":"AssumeRole","userIdentity":{"accessKeyId":"AKIATEST"}}'


def _expected_signature(body: bytes) -> str:
    """Reproduce the canary receiver's expected signature format.

    Mirrors `src/honeypot_mcp/canary.py:_handle_cloud_event`:
        expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    """
    return "sha256=" + hmac.new(_TEST_SECRET.encode(), body, hashlib.sha256).hexdigest()


def _load_module(path: Path, name: str, fake_modules: dict[str, types.ModuleType] | None = None):
    """Load a Python file as a module without registering it under its real
    name. Some forwarders import azure.functions / functions_framework which
    aren't available in the test env — caller can pre-register stubs."""
    if fake_modules:
        for k, v in fake_modules.items():
            sys.modules.setdefault(k, v)
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_aws_forwarder_signature_accepted_by_receiver():
    """AWS Lambda's `_sign` must produce the exact signature the receiver
    expects so the receiver won't 401 the request."""
    aws_mod = _load_module(_EXAMPLES / "aws" / "lambda_function.py", "aws_forwarder")
    sig = aws_mod._sign(_TEST_SECRET, _TEST_PAYLOAD)
    assert sig == _expected_signature(_TEST_PAYLOAD)
    assert sig.startswith("sha256=")


def test_aws_forwarder_filters_interesting_events():
    """Failure-flagged events should always forward; benign reads should not."""
    aws_mod = _load_module(_EXAMPLES / "aws" / "lambda_function.py", "aws_forwarder_filter")

    # Interesting because eventName is in the allow-list
    assert aws_mod._is_interesting({"eventName": "ConsoleLogin"})
    assert aws_mod._is_interesting({"eventName": "AssumeRole"})
    # Interesting because errorCode is set
    assert aws_mod._is_interesting({"eventName": "DescribeInstances", "errorCode": "AccessDenied"})
    # Not interesting
    assert not aws_mod._is_interesting({"eventName": "DescribeInstances"})


def test_azure_forwarder_signature_accepted_by_receiver():
    """Azure Function shares the same signing helper layout — verify directly."""
    # azure.functions isn't installed in CI; stub the namespace so import succeeds.
    fake_az = types.ModuleType("azure")
    fake_az_func = types.ModuleType("azure.functions")

    class _FakeApp:
        def event_hub_message_trigger(self, **_kwargs):
            def decorator(fn):
                return fn

            return decorator

    fake_az_func.FunctionApp = _FakeApp  # type: ignore[attr-defined]
    fake_az_func.EventHubEvent = object  # type: ignore[attr-defined]
    fake_az.functions = fake_az_func  # type: ignore[attr-defined]

    azure_mod = _load_module(
        _EXAMPLES / "azure" / "function_app.py",
        "azure_forwarder",
        fake_modules={"azure": fake_az, "azure.functions": fake_az_func},
    )
    sig = azure_mod._sign(_TEST_SECRET, _TEST_PAYLOAD)
    assert sig == _expected_signature(_TEST_PAYLOAD)


def test_azure_forwarder_filters_interesting_records():
    fake_az = types.ModuleType("azure")
    fake_az_func = types.ModuleType("azure.functions")

    class _FakeApp:
        def event_hub_message_trigger(self, **_kwargs):
            def decorator(fn):
                return fn

            return decorator

    fake_az_func.FunctionApp = _FakeApp  # type: ignore[attr-defined]
    fake_az_func.EventHubEvent = object  # type: ignore[attr-defined]
    fake_az.functions = fake_az_func  # type: ignore[attr-defined]

    azure_mod = _load_module(
        _EXAMPLES / "azure" / "function_app.py",
        "azure_forwarder_filter",
        fake_modules={"azure": fake_az, "azure.functions": fake_az_func},
    )

    assert azure_mod._is_interesting(
        {"operationName": "Microsoft.Authorization/roleAssignments/write"}
    )
    assert azure_mod._is_interesting({"category": "SignInLogs"})
    assert azure_mod._is_interesting(
        {"operationName": "Microsoft.Compute/virtualMachines/read", "status": {"value": "Failed"}}
    )
    # Plain successful read of a non-interesting resource → drop
    assert not azure_mod._is_interesting(
        {"operationName": "Microsoft.Compute/virtualMachines/read"}
    )


def test_gcp_forwarder_signature_accepted_by_receiver():
    fake_ff = types.ModuleType("functions_framework")

    def _cloud_event(fn):
        return fn

    fake_ff.cloud_event = _cloud_event  # type: ignore[attr-defined]

    gcp_mod = _load_module(
        _EXAMPLES / "gcp" / "main.py",
        "gcp_forwarder",
        fake_modules={"functions_framework": fake_ff},
    )
    sig = gcp_mod._sign(_TEST_SECRET, _TEST_PAYLOAD)
    assert sig == _expected_signature(_TEST_PAYLOAD)


def test_gcp_forwarder_requires_principal_email():
    """Service-account / system calls without an explicit principalEmail
    can't trigger honeytokens, so we drop them at the function rather than
    spend an HTTP roundtrip."""
    fake_ff = types.ModuleType("functions_framework")

    def _cloud_event(fn):
        return fn

    fake_ff.cloud_event = _cloud_event  # type: ignore[attr-defined]

    gcp_mod = _load_module(
        _EXAMPLES / "gcp" / "main.py",
        "gcp_forwarder_filter",
        fake_modules={"functions_framework": fake_ff},
    )

    # Right service, has principal → interesting
    assert gcp_mod._is_interesting(
        {
            "protoPayload": {
                "serviceName": "iam.googleapis.com",
                "authenticationInfo": {"principalEmail": "attacker@evil.example"},
            }
        }
    )
    # Right service, missing principal → drop
    assert not gcp_mod._is_interesting(
        {"protoPayload": {"serviceName": "iam.googleapis.com", "authenticationInfo": {}}}
    )
    # Uninteresting service → drop even with principal
    assert not gcp_mod._is_interesting(
        {
            "protoPayload": {
                "serviceName": "compute.googleapis.com",
                "authenticationInfo": {"principalEmail": "attacker@evil.example"},
            }
        }
    )


@pytest.mark.asyncio
async def test_aws_signature_passes_real_receiver_signature_check():
    """End-to-end: the AWS forwarder's signature would be accepted by the
    actual canary receiver's `hmac.compare_digest` check.
    """
    aws_mod = _load_module(_EXAMPLES / "aws" / "lambda_function.py", "aws_forwarder_e2e")
    sig = aws_mod._sign(_TEST_SECRET, _TEST_PAYLOAD)
    # The receiver computes `expected` exactly this way and compare_digests
    # against the X-HoneyPot-Signature header.
    expected_at_receiver = (
        "sha256=" + hmac.new(_TEST_SECRET.encode(), _TEST_PAYLOAD, hashlib.sha256).hexdigest()
    )
    assert hmac.compare_digest(sig, expected_at_receiver)
