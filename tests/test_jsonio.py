import json

import pytest

from dspy_security_bench.jsonio import MAX_NUMBER_CHARACTERS, decode_json_object, read_json_object
from dspy_security_bench.ledger.cli import _read_json as read_ledger_json
from dspy_security_bench.supplychain.cli import main


@pytest.mark.parametrize(
    "raw",
    [
        b'{"private-key":1,"private-key":2}',
        b'{"nested":{"private-key":1,"private-key":2}}',
        b'{"x":NaN}',
        b'{"x":Infinity}',
        b'{"x":-Infinity}',
        b'{"x":1e999}',
        b'{"x":"\\ud800"}',
        b'{"\\udfff":1}',
        b'{"x":"\xff"}',
        b'{"x":' + b"[" * 105 + b"0" + b"]" * 105 + b"}",
        b"[]",
        b'{"private-key":',
    ],
)
def test_reader_rejects_ambiguous_or_nonportable_json_without_echoing_values(tmp_path, raw):
    path = tmp_path / "input.json"
    path.write_bytes(raw)
    with pytest.raises(ValueError) as caught:
        read_json_object(path, 10000)
    assert "private-key" not in str(caught.value)


def test_reader_preserves_valid_unicode_and_numeric_types(tmp_path):
    expected = {"text": "café 🌍", "large": 2**64, "decimal": 1.25, "flag": False}
    path = tmp_path / "input.json"
    path.write_text(json.dumps(expected), encoding="utf-8")
    assert read_json_object(path, path.stat().st_size) == expected
    with pytest.raises(ValueError, match="exceeds"):
        read_json_object(path, path.stat().st_size - 1)


def test_ledger_reader_rejects_duplicate_trust_threshold(tmp_path):
    path = tmp_path / "root.json"
    path.write_text('{"roles":{"root":{"threshold":2,"threshold":1}}}')
    with pytest.raises(ValueError, match="duplicate member"):
        read_ledger_json(path)


def test_bom_cli_rejects_duplicate_policy_before_creating_output(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text('{"bomFormat":"private-value","bomFormat":"CycloneDX"}')
    out = tmp_path / "output.json"
    assert (
        main(
            [
                "import-mlbom",
                str(path),
                "--inventory-id",
                "demo",
                "--out",
                str(out),
                "--report-out",
                str(tmp_path / "report.json"),
            ]
        )
        == 2
    )
    assert not out.exists()
    assert "duplicate member" in capsys.readouterr().err


@pytest.mark.parametrize("number", [
    b"9" * 129,
    b"-" + b"9" * 128,
    b"0." + b"1" * 127,
    b"1e" + b"0" * 127,
    b"-1.0e-" + b"0" * 123,
])
def test_numeric_tokens_are_bounded_before_conversion(number):
    raw = b'{"private-key":' + number + b"}"
    with pytest.raises(ValueError, match="numeric tokens") as caught:
        decode_json_object(raw, 1000)
    assert "private-key" not in str(caught.value)
    assert number.decode() not in str(caught.value)


def test_numeric_boundary_preserves_integer_types_and_normal_floats():
    digits = b"9" * MAX_NUMBER_CHARACTERS
    assert decode_json_object(b'{"x":' + digits + b"}", 1000)["x"] == int(digits)
    assert decode_json_object(b'{"x":-2.5e-3}', 1000)["x"] == -0.0025


def test_signed_statement_reader_uses_the_same_numeric_budget():
    import base64

    from dspy_security_bench.jsonio import decode_base64_statement

    raw = b'{"x":' + b"9" * 129 + b"}"
    with pytest.raises(ValueError, match="numeric tokens"):
        decode_base64_statement(base64.b64encode(raw).decode())
