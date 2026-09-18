import base64
import json
from copy import deepcopy

import pytest

from dspy_security_bench.jsonio import decode_base64_statement, decode_json_object
from dspy_security_bench.ledger.proof import _review_predicate
from dspy_security_bench.ledger.rereview import _predicate
from dspy_security_bench.ledger.trust_recovery_attestation import _inspect_envelope
from dspy_security_bench.quorum.proof import PAYLOAD_TYPE, verify_review_envelope


def envelope(raw):
    return {
        "payloadType": PAYLOAD_TYPE,
        "payload": base64.b64encode(raw).decode(),
        "signatures": [{"keyid": "fixture", "sig": ""}],
    }


def verify(kind, value):
    if kind == "review":
        _, errors = verify_review_envelope(value, {}, {}, evaluation_time=10)
        return errors
    _, errors = _inspect_envelope(
        value,
        {},
        {},
        {},
        {"event_type": "compromise-detected"},
        evaluation_time=10,
        expected_previous_sha256="0" * 64,
    )
    return [message for messages in errors.values() for message in messages]


@pytest.mark.parametrize("kind", ["review", "recovery"])
@pytest.mark.parametrize(
    "raw",
    [
        b'{"predicate":{},"predicate":{"decision":"evidence-sufficient"}}',
        b'{"predicate":{"x":NaN}}',
        b'{"predicate":{"x":1e999}}',
        b'{"predicate":{"x":"\\udfff"}}',
        b"[]",
        b"null",
        b'"x"',
        b'{"x":' + b"[" * 1100 + b"0" + b"]" * 1100 + b"}",
        b'{"x":"' + b"x" * 1_000_001 + b'"}',
    ],
    ids=["duplicate", "nan", "overflow", "surrogate", "array", "null", "string", "depth", "size"],
)
def test_signed_statement_decoders_reject_invalid_payloads_without_exceptions(kind, raw):
    assert verify(kind, envelope(raw))


def paths(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield prefix + (key,)
            yield from paths(child, prefix + (key,))
    elif isinstance(value, list):
        for key, child in enumerate(value):
            yield prefix + (key,)
            yield from paths(child, prefix + (key,))


@pytest.mark.parametrize("kind", ["review", "recovery"])
def test_malformed_predicate_shapes_return_invalid_evidence(kind):
    statement = {
        "_type": "https://in-toto.io/Statement/v1",
        "subject": [],
        "predicateType": "fixture",
        "predicate": {
            "reviewer": {
                "signer_id": "a",
                "role": "r",
                "organization_id": "o",
                "key_sha256": "0" * 64,
            },
            "actor": {
                "signer_id": "a",
                "recovery_role": "r",
                "organization_id": "o",
                "key_sha256": "0" * 64,
            },
            "decision": "evidence-sufficient",
            "claim_ids": ["claim-a"],
            "reason_codes": ["evidence-verified"],
            "issued_at": 1,
            "expires_at": 20,
            "occurred_at": 1,
            "nonce": "fixture-nonce",
            "sequence": 1,
        },
    }
    attempts = 0
    for path in paths(statement):
        for value in (None, True, 0, [], {}, "x", [{}]):
            changed = deepcopy(statement)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            raw = json.dumps(changed, sort_keys=True, separators=(",", ":")).encode()
            assert verify(kind, envelope(raw)), (kind, path, value)
            attempts += 1
    assert attempts > 100


def test_auxiliary_predicate_readers_do_not_disagree_on_duplicate_members():
    value = envelope(b'{"predicate":{},"predicate":{"reviewer":{"signer_id":"x"}}}')
    with pytest.raises(ValueError, match="readable predicate"):
        _review_predicate(value)
    assert _predicate(value) == {}


def test_byte_decoder_and_base64_boundaries():
    assert decode_json_object(b'{"x":0}', 7) == {"x": 0}
    with pytest.raises(ValueError, match="exceeds"):
        decode_json_object(b'{"x":0}', 6)
    for value in (None, [], {}, 1, "é", "not-base64!"):
        with pytest.raises(ValueError):
            decode_base64_statement(value)
