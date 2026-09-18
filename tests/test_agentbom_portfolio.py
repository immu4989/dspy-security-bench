import json
from copy import deepcopy
from pathlib import Path

import jsonschema
import pytest

from dspy_security_bench.supplychain.cli import main
from dspy_security_bench.supplychain.portfolio import (
    MANIFEST_TYPE,
    build_portfolio_artifacts,
    verify_portfolio_pack,
    write_portfolio_pack,
)

ROOT = Path(__file__).resolve().parents[1]
EXAMPLES = ROOT / "examples"


def policy():
    return json.loads((EXAMPLES / "ai-bom-disclosure-policy.json").read_text())


def manifest():
    return {
        "schema_version": 1,
        "manifest_type": MANIFEST_TYPE,
        "suppliers": [
            {
                "supplier_id": "fictional-b",
                "cyclonedx_source": "cyclonedx-mlbom-1.7.json",
                "spdx_source": "spdx-ai-3.0.1.json",
            },
            {
                "supplier_id": "fictional-a",
                "cyclonedx_source": "cyclonedx-mlbom-1.7.json",
                "spdx_source": "spdx-ai-3.0.1.json",
            },
        ],
    }


def test_portfolio_uses_one_policy_with_deterministic_labeled_evidence(tmp_path):
    first, second = tmp_path / "one", tmp_path / "two"
    report = write_portfolio_pack(first, manifest(), policy(), EXAMPLES)
    write_portfolio_pack(second, manifest(), policy(), EXAMPLES)
    assert report["summary"] == {
        "suppliers": 2,
        "evaluated": 2,
        "input_invalid": 0,
        "owner_review_required": 2,
        "requirements_met": 0,
        "finding_count": 8,
        "complete": True,
        "automatic_approvals": 0,
    }
    assert [row["supplier_id"] for row in report["suppliers"]] == ["fictional-a", "fictional-b"]
    for path in first.rglob("*"):
        if path.is_file():
            assert path.read_bytes() == (second / path.relative_to(first)).read_bytes()
    assert verify_portfolio_pack(first, manifest(), policy(), EXAMPLES) == ()
    assert b"private/model.bin" not in b"".join(
        build_portfolio_artifacts(manifest(), policy(), EXAMPLES).values()
    )
    with pytest.raises(FileExistsError):
        write_portfolio_pack(first, manifest(), policy(), EXAMPLES)


def test_bad_submission_is_not_zero_finding_pass_and_does_not_hide_other_supplier(tmp_path):
    data = manifest()
    data["suppliers"][0]["spdx_source"] = "private-supplier-path-missing.json"
    artifacts = build_portfolio_artifacts(data, policy(), EXAMPLES)
    report = json.loads(artifacts["portfolio.json"])
    assert report["summary"]["complete"] is False
    assert report["summary"]["evaluated"] == 1
    invalid = report["suppliers"][1]
    assert invalid["status"] == "input_invalid"
    assert invalid["finding_count"] is None
    assert invalid["intake_manifest_sha256"] is None
    assert invalid["error_code"] == "source_unreadable_or_invalid_json"
    assert b"private-supplier-path" not in b"".join(artifacts.values())
    destination = tmp_path / "partial"
    write_portfolio_pack(destination, data, policy(), EXAMPLES)
    assert verify_portfolio_pack(destination, data, policy(), EXAMPLES) == ()


@pytest.mark.parametrize("bad_source", ['{"secret":1,"secret":2}', '{"wrong-profile":true}'])
def test_invalid_json_or_unsupported_profile_is_a_submission_error(tmp_path, bad_source):
    (tmp_path / "bad.json").write_text(bad_source)
    (tmp_path / "spdx.json").write_bytes((EXAMPLES / "spdx-ai-3.0.1.json").read_bytes())
    data = manifest()
    for entry in data["suppliers"]:
        entry.update(cyclonedx_source="bad.json", spdx_source="spdx.json")
    report = json.loads(build_portfolio_artifacts(data, policy(), tmp_path)["portfolio.json"])
    assert report["summary"]["input_invalid"] == 2
    assert report["summary"]["requirements_met"] == 0


@pytest.mark.parametrize(
    "path", ["../escape.json", "/absolute.json", "a/../b", "a//b", "a/./b", "a\\b", "", "\x00"]
)
def test_manifest_rejects_unsafe_paths_before_writing(tmp_path, path):
    data = manifest()
    data["suppliers"][0]["spdx_source"] = path
    with pytest.raises(ValueError):
        write_portfolio_pack(tmp_path / "out", data, policy(), EXAMPLES)
    assert not (tmp_path / "out").exists()


def test_source_symlink_cannot_escape_explicit_root(tmp_path):
    sources = tmp_path / "sources"
    sources.mkdir()
    (sources / "cdx.json").symlink_to(EXAMPLES / "cyclonedx-mlbom-1.7.json")
    data = manifest()
    for entry in data["suppliers"]:
        entry["cyclonedx_source"] = "cdx.json"
    result = json.loads(build_portfolio_artifacts(data, policy(), sources)["portfolio.json"])
    assert result["summary"]["input_invalid"] == 2


@pytest.mark.parametrize("mutation", ["duplicate", "unknown", "bool", "too-many", "html-id"])
def test_manifest_is_bounded_and_strict(mutation):
    data = manifest()
    if mutation == "duplicate":
        data["suppliers"][1]["supplier_id"] = data["suppliers"][0]["supplier_id"]
    elif mutation == "unknown":
        data["suppliers"][0]["extra"] = True
    elif mutation == "bool":
        data["schema_version"] = True
    elif mutation == "too-many":
        data["suppliers"] *= 13
    else:
        data["suppliers"][0]["supplier_id"] = "<script>alert(1)</script>"
    with pytest.raises(ValueError):
        build_portfolio_artifacts(data, policy(), EXAMPLES)


@pytest.mark.parametrize("label", [
    "con", "prn", "aux", "nul", *[f"com{i}" for i in range(1, 10)],
    *[f"lpt{i}" for i in range(1, 10)], "case-001\n",
])
def test_manifest_and_schema_reject_nonportable_supplier_ids_before_output(tmp_path, label):
    data = manifest()
    data["suppliers"][0]["supplier_id"] = label
    schema = json.loads((ROOT / "dspy_security_bench/schemas/agentbom-ai-portfolio-manifest.schema.json").read_text())
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(data, schema)
    with pytest.raises(ValueError, match="supplier IDs"):
        write_portfolio_pack(tmp_path / "pack", data, policy(), EXAMPLES)
    assert not (tmp_path / "pack").exists()


@pytest.mark.parametrize("label", ["case-con", "company-1", "com10", "lpt10", "a" * 64])
def test_nonreserved_supplier_ids_remain_usable(label):
    data = manifest()
    data["suppliers"][0]["supplier_id"] = label
    schema = json.loads((ROOT / "dspy_security_bench/schemas/agentbom-ai-portfolio-manifest.schema.json").read_text())
    jsonschema.validate(data, schema)
    assert f"suppliers/{label}/manifest.json" in build_portfolio_artifacts(data, policy(), EXAMPLES)


@pytest.mark.parametrize(
    "mutation",
    ["edited", "edited-html", "missing", "extra", "extra-dir", "symlink", "policy", "manifest"],
)
def test_verification_rejects_any_pack_or_input_change(tmp_path, mutation):
    destination = tmp_path / "pack"
    data, owner_policy = manifest(), policy()
    write_portfolio_pack(destination, data, owner_policy, EXAMPLES)
    if mutation == "edited":
        (destination / "review.md").write_text("approved")
    elif mutation == "edited-html":
        (destination / "review.html").write_text("approved")
    elif mutation == "missing":
        (destination / "suppliers/fictional-a/review.md").unlink()
    elif mutation == "extra":
        (destination / "secret.txt").write_text("private")
    elif mutation == "extra-dir":
        (destination / "extra").mkdir()
    elif mutation == "symlink":
        (destination / "suppliers").rename(destination / "original")
        (destination / "suppliers").symlink_to(destination / "original", target_is_directory=True)
    elif mutation == "policy":
        owner_policy["owner"] = "different owner"
    else:
        data["suppliers"].reverse()
    assert verify_portfolio_pack(destination, data, owner_policy, EXAMPLES)


def test_invalid_common_policy_aborts_instead_of_labeling_suppliers_invalid(tmp_path):
    invalid = deepcopy(policy())
    invalid["spdx"]["required_ai_fields"] = ["not-a-field"]
    with pytest.raises(ValueError):
        write_portfolio_pack(tmp_path / "pack", manifest(), invalid, EXAMPLES)
    assert not (tmp_path / "pack").exists()


def test_cli_preserves_artifacts_on_gate_and_partial_input(tmp_path):
    source = tmp_path / "manifest.json"
    data = manifest()
    source.write_text(json.dumps(data))
    args = [
        "--manifest",
        str(source),
        "--policy",
        str(EXAMPLES / "ai-bom-disclosure-policy.json"),
        "--source-root",
        str(EXAMPLES),
    ]
    pack = tmp_path / "review"
    assert main(["intake-ai-portfolio", *args, "--out-dir", str(pack), "--fail-on-findings"]) == 1
    assert main(["verify-ai-portfolio", str(pack), *args]) == 0
    data["suppliers"][0]["spdx_source"] = "missing.json"
    source.write_text(json.dumps(data))
    partial = tmp_path / "partial"
    assert main(["intake-ai-portfolio", *args, "--out-dir", str(partial)]) == 2
    assert (partial / "review.md").is_file()


def test_committed_manifest_and_portfolio_schema():
    data = json.loads((EXAMPLES / "ai-supplier-portfolio.json").read_text())
    report = json.loads(build_portfolio_artifacts(data, policy(), EXAMPLES)["portfolio.json"])
    for name, instance in [
        ("agentbom-ai-portfolio-manifest", data),
        ("agentbom-ai-portfolio-report", report),
    ]:
        schema = json.loads((ROOT / f"dspy_security_bench/schemas/{name}.schema.json").read_text())
        jsonschema.Draft202012Validator.check_schema(schema)
        validator = jsonschema.Draft202012Validator(schema)
        validator.validate(instance)
        with pytest.raises(jsonschema.ValidationError):
            validator.validate({**instance, "unexpected": True})
