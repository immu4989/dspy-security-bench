from __future__ import annotations

import hashlib
import json
from pathlib import Path

import jsonschema

from dspy_security_bench.assurance.case import analyze_case, built_in_case, seal_case
from dspy_security_bench.assurance.cli import _demo_evidence, main
from dspy_security_bench.assurance.federal import (
    PACK_FILES,
    export_review_pack,
    verify_review_pack,
)
from dspy_security_bench.mission.loader import canonical_sha256

ROOT = Path(__file__).resolve().parents[1]


def _report(tmp_path, *, omit_kind=None):
    case = built_in_case("critical-infrastructure")
    evidence = _demo_evidence()
    for item in case["evidence"]:
        payload = evidence[item["evidence_kind"]]
        path = tmp_path / item["path"]
        path.parent.mkdir(parents=True, exist_ok=True)
        if item["evidence_kind"] != omit_kind:
            path.write_text(json.dumps(payload))
        item["expected_sha256"] = canonical_sha256(payload)
        item["owner"] = "test-evidence-owner"
    case["decision_owner"] = "test-decision-owner"
    return analyze_case(seal_case(case), tmp_path)


def test_exported_review_pack_is_closed_recomputable_and_non_certifying(tmp_path):
    report = _report(tmp_path)
    pack = tmp_path / "pack"
    manifest = export_review_pack(report, tmp_path, pack)
    assert verify_review_pack(pack, tmp_path) == ()
    assert {path.name for path in pack.iterdir()} == {*PACK_FILES, "pack-manifest.json"}
    assert manifest["automatic_control_determinations"] == 0
    assert manifest["automatic_risk_acceptances"] == 0
    assert manifest["automatic_authorizations_to_operate"] == 0
    assert json.loads((pack / "poam-input.json").read_text())["open_item_count"] == 0
    index = json.loads((pack / "evidence-index.json").read_text())
    assert index["payloads_embedded"] is False
    assert len(index["evidence"]) == 8
    schema = json.loads(
        (
            ROOT / "dspy_security_bench/schemas/assurance-review-pack-manifest.schema.json"
        ).read_text()
    )
    jsonschema.validate(manifest, schema)


def test_review_pack_preserves_missing_claim_as_owner_poam_input(tmp_path):
    report = _report(tmp_path, omit_kind="containment")
    pack = tmp_path / "pack"
    export_review_pack(report, tmp_path, pack)
    assert verify_review_pack(pack, tmp_path) == ()
    poam = json.loads((pack / "poam-input.json").read_text())
    assert poam["open_item_count"] == 1
    assert poam["items"][0]["claim_id"] == "runtime-containment"
    assert poam["items"][0]["owner"] == "owner-assignment-required"
    assert poam["automatic_deadlines_invented"] == 0


def test_pack_detects_file_tamper_semantic_regeneration_and_undeclared_files(tmp_path):
    report = _report(tmp_path)
    pack = tmp_path / "pack"
    export_review_pack(report, tmp_path, pack)
    poam = pack / "poam-input.json"
    original = poam.read_text()
    poam.write_text(original + " ")
    assert "file digest mismatch: poam-input.json" in verify_review_pack(pack, tmp_path)

    export_review_pack(report, tmp_path, pack, force=True)
    manifest_path = pack / "pack-manifest.json"
    manifest = json.loads(manifest_path.read_text())
    altered = json.loads((pack / "poam-input.json").read_text())
    altered["disclaimer"] = "changed"
    raw = json.dumps(altered, indent=2, sort_keys=True) + "\n"
    (pack / "poam-input.json").write_text(raw)
    manifest["files"]["poam-input.json"] = hashlib.sha256(raw.encode()).hexdigest()
    manifest.pop("pack_sha256")
    manifest["pack_sha256"] = canonical_sha256(manifest)
    manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n")
    assert "generated artifact does not recompute: poam-input.json" in verify_review_pack(
        pack, tmp_path
    )

    export_review_pack(report, tmp_path, pack, force=True)
    (pack / "undeclared.txt").write_text("not part of the closed pack")
    assert "pack contains undeclared files: undeclared.txt" in verify_review_pack(pack, tmp_path)


def test_federal_review_cli_exports_and_verifies(tmp_path, capsys):
    report = _report(tmp_path)
    report_path = tmp_path / "report.json"
    report_path.write_text(json.dumps(report))
    pack = tmp_path / "pack"
    assert (
        main(
            [
                "federal-pack",
                str(report_path),
                "--evidence-root",
                str(tmp_path),
                "--out-dir",
                str(pack),
            ]
        )
        == 0
    )
    assert "control determinations=0" in capsys.readouterr().out
    assert main(["federal-verify", str(pack), "--evidence-root", str(tmp_path)]) == 0
    assert "verified federal review pack" in capsys.readouterr().out
