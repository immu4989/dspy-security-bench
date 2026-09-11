from __future__ import annotations

import json
from pathlib import Path

import jsonschema

from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.root_view_vectors import (
    MANIFEST_FILE,
    generate_root_view_vector_pack,
    verify_root_view_vector_pack,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[1]
COMMITTED_PACK = REPO_ROOT / "interop" / "root-view-quorum-v1"


def _json_files(root: Path) -> dict[str, bytes]:
    return {
        path.relative_to(root).as_posix(): path.read_bytes()
        for path in sorted(root.rglob("*.json"))
    }


def test_committed_known_answer_pack_executes_every_case():
    assert verify_root_view_vector_pack(COMMITTED_PACK) == ()
    manifest = json.loads((COMMITTED_PACK / MANIFEST_FILE).read_text())
    assert len(manifest["cases"]) == 8
    assert {item["case_id"] for item in manifest["cases"]} == {
        "matching-quorum",
        "lagging-view-preserved",
        "same-version-conflict",
        "newer-root-reported",
        "duplicate-observer",
        "nonce-mismatch",
        "invalid-observer-signature",
        "rehashed-summary-tamper",
    }


def test_generator_is_byte_deterministic_across_directories(tmp_path):
    first = tmp_path / "first"
    second = tmp_path / "second"
    generate_root_view_vector_pack(first)
    generate_root_view_vector_pack(second)
    assert _json_files(first) == _json_files(second)
    assert _json_files(first) == _json_files(COMMITTED_PACK)


def test_pack_contains_no_private_key_material():
    assert not list(COMMITTED_PACK.rglob("*.pem"))
    assert not list(COMMITTED_PACK.rglob("*private*"))
    assert b"PRIVATE KEY" not in b"".join(_json_files(COMMITTED_PACK).values())
    assert all(
        raw.endswith(b"\n") and b"\r\n" not in raw
        for raw in _json_files(COMMITTED_PACK).values()
    )


def test_one_byte_vector_drift_is_detected_before_execution(tmp_path):
    pack = tmp_path / "pack"
    generate_root_view_vector_pack(pack)
    target = pack / "policy.json"
    target.write_text(target.read_text() + "\n")
    assert "policy.json: file SHA-256 does not match the manifest" in (
        verify_root_view_vector_pack(pack)
    )


def test_rehashed_wrong_expected_outcome_cannot_impersonate_known_answer_v1(tmp_path):
    pack = tmp_path / "pack"
    generate_root_view_vector_pack(pack)
    path = pack / MANIFEST_FILE
    manifest = json.loads(path.read_text())
    manifest["cases"][0]["expected_status"] = "newer_root_reported"
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    errors = verify_root_view_vector_pack(pack)
    assert "manifest_sha256 does not match immutable known-answer v1" in errors


def test_undeclared_or_unsafe_vector_files_fail_closed(tmp_path):
    pack = tmp_path / "pack"
    generate_root_view_vector_pack(pack)
    (pack / "private-key.pem").write_text("not actually a key\n")
    assert any("unexpected files" in item for item in verify_root_view_vector_pack(pack))

    (pack / "private-key.pem").unlink()
    path = pack / MANIFEST_FILE
    manifest = json.loads(path.read_text())
    manifest["file_sha256"]["../escape.json"] = "0" * 64
    manifest.pop("manifest_sha256")
    manifest["manifest_sha256"] = canonical_sha256(manifest)
    path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    assert any("unsafe path" in item for item in verify_root_view_vector_pack(pack))


def test_vector_pack_rejects_symbolic_links_even_when_bytes_match(tmp_path):
    pack = tmp_path / "pack"
    generate_root_view_vector_pack(pack)
    policy = pack / "policy.json"
    outside = tmp_path / "same-policy.json"
    policy.replace(outside)
    policy.symlink_to(outside)
    assert any("symbolic links" in item for item in verify_root_view_vector_pack(pack))


def test_manifest_validates_against_strict_schema():
    manifest = json.loads((COMMITTED_PACK / MANIFEST_FILE).read_text())
    schema = json.loads(
        (
            REPO_ROOT
            / "dspy_security_bench"
            / "schemas"
            / "assuranceledger-root-view-vector-manifest.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(manifest)


def test_cli_generates_and_verifies_vector_pack(tmp_path):
    output = tmp_path / "vectors"
    assert ledger_main(["generate-root-view-vectors", "--out-dir", str(output)]) == 0
    assert ledger_main(["verify-root-view-vectors", str(output)]) == 0
    assert _json_files(output) == _json_files(COMMITTED_PACK)


def test_generator_refuses_to_overwrite_an_existing_directory(tmp_path):
    output = tmp_path / "vectors"
    output.mkdir()
    try:
        generate_root_view_vector_pack(output)
    except ValueError as exc:
        assert "vector output already exists" in str(exc)
    else:
        raise AssertionError("existing vector directory was overwritten")
