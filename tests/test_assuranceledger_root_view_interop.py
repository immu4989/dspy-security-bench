from __future__ import annotations

import hashlib
import json
import shutil
import subprocess
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.ledger.capabilities import default_schema_root
from dspy_security_bench.ledger.cli import main as ledger_main
from dspy_security_bench.ledger.root_view_interop import (
    CLAIM_BOUNDARY,
    build_root_view_interop_report,
    verify_root_view_interop_report,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPO_ROOT = Path(__file__).resolve().parents[1]
PACK = REPO_ROOT / "interop" / "root-view-quorum-v1"
RUNNER = REPO_ROOT / "interop" / "root-view-quorum-node" / "verify.mjs"
NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")


def _node_result() -> dict:
    completed = subprocess.run(
        [str(NODE), str(RUNNER), str(PACK)],
        cwd=REPO_ROOT,
        capture_output=True,
        check=False,
        text=True,
        timeout=30,
    )
    assert completed.returncode == 0, completed.stderr
    return json.loads(completed.stdout)


def test_report_binds_two_sources_and_all_case_agreements():
    report = build_root_view_interop_report(
        PACK,
        _node_result(),
        RUNNER,
        implementation_language="javascript",
    )
    predicate = report["statement"]["predicate"]
    assert predicate["summary"] == {
        "agreement_count": 8,
        "automatic_actions": 0,
        "case_count": 8,
        "disagreement_count": 0,
        "implementation_count": 2,
        "status": "interoperability_observed",
    }
    assert [item["language"] for item in predicate["implementations"]] == [
        "python",
        "javascript",
    ]
    assert len(report["statement"]["subject"]) == 4
    manifest_subject = report["statement"]["subject"][0]
    assert (
        manifest_subject["digest"]["sha256"]
        == hashlib.sha256((PACK / "vector-manifest.json").read_bytes()).hexdigest()
    )
    assert all(item["agreement"] for item in predicate["case_agreements"])
    assert predicate["case_agreements"][-1]["external_verifier_accepted"] is False
    assert verify_root_view_interop_report(report, PACK, RUNNER) == ()


def test_report_validates_against_strict_schema():
    report = build_root_view_interop_report(
        PACK,
        _node_result(),
        RUNNER,
        implementation_language="javascript",
    )
    schema = json.loads(
        (
            default_schema_root() / "assuranceledger-root-view-interop-evidence.schema.json"
        ).read_text()
    )
    jsonschema.Draft202012Validator(schema).validate(report)


def test_external_result_must_bind_exact_supplied_source(tmp_path):
    copied = tmp_path / "verify.mjs"
    copied.write_bytes(RUNNER.read_bytes() + b"\n")
    with pytest.raises(ValueError, match="does not bind the supplied source bytes"):
        build_root_view_interop_report(
            PACK,
            _node_result(),
            copied,
            implementation_language="javascript",
        )


def test_self_rehashed_semantic_tampering_fails_exact_recomputation():
    report = build_root_view_interop_report(
        PACK,
        _node_result(),
        RUNNER,
        implementation_language="javascript",
    )
    tampered = deepcopy(report)
    tampered["statement"]["predicate"]["summary"]["agreement_count"] = 7
    tampered["statement"]["predicate"]["summary"]["disagreement_count"] = 1
    tampered.pop("report_sha256")
    tampered["report_sha256"] = canonical_sha256(tampered)
    assert "RootViewInteropEvidence does not recompute exactly" in (
        verify_root_view_interop_report(tampered, PACK, RUNNER)
    )


def test_result_expectation_tampering_is_rejected_even_when_reported_as_passing():
    result = _node_result()
    result["cases"][0]["expected_status"] = "same_version_root_conflict"
    with pytest.raises(ValueError, match="changed the expectation"):
        build_root_view_interop_report(
            PACK,
            result,
            RUNNER,
            implementation_language="javascript",
        )


def test_external_semantic_disagreement_cannot_be_labeled_interoperable():
    result = _node_result()
    result["cases"][0]["observed_status"] = "same_version_root_conflict"
    with pytest.raises(ValueError, match="disagrees with the reference corpus"):
        build_root_view_interop_report(
            PACK,
            result,
            RUNNER,
            implementation_language="javascript",
        )


def test_cli_builds_and_reverifies_retained_evidence(tmp_path):
    result_path = tmp_path / "node-result.json"
    result_path.write_text(json.dumps(_node_result(), indent=2, sort_keys=True) + "\n")
    report_path = tmp_path / "root-view-interop.report.json"
    assert (
        ledger_main(
            [
                "evaluate-root-view-interop",
                str(PACK),
                str(result_path),
                "--implementation-source",
                str(RUNNER),
                "--implementation-language",
                "javascript",
                "--out",
                str(report_path),
            ]
        )
        == 0
    )
    assert (
        ledger_main(
            [
                "verify-root-view-interop",
                str(report_path),
                str(PACK),
                "--implementation-source",
                str(RUNNER),
            ]
        )
        == 0
    )


def test_claim_boundary_does_not_overstate_execution_or_certification():
    assert "not proof" in CLAIM_BOUNDARY
    assert "certification" in CLAIM_BOUNDARY
    assert "ATO" in CLAIM_BOUNDARY
