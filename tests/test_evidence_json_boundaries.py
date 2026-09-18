"""The same ambiguous bytes must fail at every participating evidence entry point."""

import importlib
import json

import pytest

from dspy_security_bench.assurance.case import _evaluate_evidence, built_in_case

READERS = [
    ("assurance", "_read_json", True),
    ("evalguard", "_read_json", True),
    ("containment", "_read_json", True),
    ("probes", "_read", True),
    ("causal", "_read", True),
    ("quorum", "_read_json", False),
    ("portfolio", "_read_json", False),
    ("defend", "_read_json", False),
    ("collective", "_read_json", False),
    ("schedule", "_read_json", False),
]


@pytest.mark.parametrize("module,name,bounded", READERS)
@pytest.mark.parametrize(
    "raw",
    [
        b'{"private-name":0,"private-name":1}',
        b'{"nested":{"decision":"deny","decision":"allow"}}',
        b'{"value":NaN}',
        b'{"value":1e999}',
        b'{"value":"\\ud800"}',
        b'{"value":"\xff"}',
        b"[]",
        b'{"private-key":',
    ],
)
def test_evidence_readers_reject_ambiguity_with_redacted_diagnostics(
    tmp_path, module, name, bounded, raw
):
    path = tmp_path / "evidence.json"
    path.write_bytes(raw)
    read = getattr(importlib.import_module(f"dspy_security_bench.{module}.cli"), name)
    with pytest.raises(ValueError) as caught:
        read(path, 10_000) if bounded else read(path)
    assert "private-name" not in str(caught.value)
    assert "private-key" not in str(caught.value)


@pytest.mark.parametrize("module,name,bounded", READERS)
def test_evidence_readers_preserve_valid_unicode_objects(tmp_path, module, name, bounded):
    path = tmp_path / "evidence.json"
    expected = {"owner": "研究", "count": 0, "enabled": False, "nested": [{"value": None}]}
    path.write_text(json.dumps(expected, ensure_ascii=False), encoding="utf-8")
    read = getattr(importlib.import_module(f"dspy_security_bench.{module}.cli"), name)
    actual = read(path, 10_000) if bounded else read(path)
    assert actual == expected


def test_assurance_case_nested_evidence_rejects_duplicate_fields_before_native_verifier(tmp_path):
    case = built_in_case("critical-infrastructure")
    entry = case["evidence"][0]
    path = tmp_path / entry["path"]
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text('{"private-key":0,"private-key":1}')
    result = _evaluate_evidence(entry, case["evaluation_time"], tmp_path)
    assert result["verification_status"] == "invalid"
    assert result["actual_sha256"] is None
    assert any("duplicate" in error for error in result["errors"])
    assert "private-key" not in json.dumps(result)
