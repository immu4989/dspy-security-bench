"""Portable studies must retain their sources, missingness, and scientific limits."""
import json
import socket
from copy import deepcopy
from importlib.resources import files

import jsonschema
import pytest
from referencing import Registry, Resource

from dspy_security_bench.mission.loader import canonical_sha256
from dspy_security_bench.scan.cli import main
from dspy_security_bench.scan.study import build_study_plan
from dspy_security_bench.scan.study_bundle import build_study_bundle, verify_study_bundle
from dspy_security_bench.scan.study_demo import build_study_demo_artifacts


def bundle_fixture():
    artifacts = build_study_demo_artifacts()
    manifest = json.loads(artifacts["manifest.json"])
    sources = {t["trial_id"]: json.loads(artifacts[t["evidence"]])
               for t in manifest["trials"] if t["status"] == "complete"}
    trials = [{k: v for k, v in t.items() if k != "evidence"} for t in manifest["trials"]]
    return build_study_bundle(manifest["plan"], trials, sources)


def rehash(value, field="bundle_sha256"):
    value[field] = canonical_sha256({k: v for k, v in value.items() if k != field})
    return value


def test_bundle_is_deterministic_deduplicated_path_free_and_schema_valid():
    bundle = bundle_fixture()
    assert bundle == bundle_fixture()
    assert len(bundle["sources"]) == 2
    assert len(bundle["study"]["trials"]) == 5
    assert verify_study_bundle(bundle)["complete_trials"] == 3
    assert all("evidence" not in trial for trial in bundle["study"]["trials"])
    assert "before.json" not in json.dumps(bundle)
    root = files("dspy_security_bench.schemas")
    registry = Registry().with_resources((name, Resource.from_contents(json.loads(root.joinpath(name).read_text())))
        for name in ("scan-evidence.schema.json", "scan-study.schema.json"))
    schema = json.loads(root.joinpath("scan-study-bundle.schema.json").read_text())
    jsonschema.Draft202012Validator.check_schema(schema)
    jsonschema.Draft202012Validator(schema, registry=registry).validate(bundle)


@pytest.mark.parametrize("mutation", [
    lambda b: b.update(schema_version=True),
    lambda b: b.update(extra="private-value"),
    lambda b: b.update(claim_boundary="approved"),
    lambda b: b.update(protocol_version="other"),
    lambda b: b["sources"].pop(next(iter(b["sources"]))),
    lambda b: b["sources"].update({"0" * 64: next(iter(b["sources"].values()))}),
    lambda b: b["study"]["summary"].update(missing_trials=0),
    lambda b: b["study"]["trials"][0].update(requirements_met=True),
    lambda b: b["study"]["trials"][0].pop("requirements_met"),
    lambda b: b["study"]["trials"].pop(),
    lambda b: b["study"]["cases"][0]["security"].update(successes=3),
    lambda b: b["study"].update(claim_boundary="independent and certified"),
    lambda b: b["study"].update(repeated_evidence_groups=[]),
])
def test_rehashed_derived_tampering_or_source_omission_fails(mutation):
    bundle = bundle_fixture()
    mutation(bundle)
    rehash(bundle["study"], "study_sha256")
    rehash(bundle)
    with pytest.raises(ValueError):
        verify_study_bundle(bundle)


def test_false_native_source_verdict_fails_even_with_all_outer_digests_rehashed():
    bundle = bundle_fixture()
    old = next(iter(bundle["sources"]))
    source = bundle["sources"].pop(old)
    source["report"]["requirements_met"] = True
    rehash(source, "evidence_sha256")
    new = source["evidence_sha256"]
    bundle["sources"][new] = source
    for trial in bundle["study"]["trials"]:
        if trial.get("evidence_sha256") == old:
            trial["evidence_sha256"] = new
    rehash(bundle["study"], "study_sha256")
    with pytest.raises(ValueError):
        verify_study_bundle(rehash(bundle))


@pytest.mark.parametrize("value", [None, [], "private-value", True, {}, {"x": 1}])
def test_invalid_source_shapes_fail(value):
    bundle = bundle_fixture()
    bundle["sources"][next(iter(bundle["sources"]))] = value
    with pytest.raises((TypeError, ValueError)):
        verify_study_bundle(rehash(bundle))


def test_independent_pins_reject_substitution():
    bundle = bundle_fixture()
    assert verify_study_bundle(bundle, bundle["study"]["plan"]["plan_sha256"], bundle["bundle_sha256"])
    with pytest.raises(ValueError, match="pin"):
        verify_study_bundle(bundle, expected_bundle_sha256="0" * 64)
    with pytest.raises(ValueError, match="pin"):
        verify_study_bundle(bundle, expected_plan_sha256="0" * 64)


def test_empty_study_bundle_preserves_null_outcomes():
    source = next(iter(bundle_fixture()["sources"].values()))
    plan = build_study_plan(source, "empty-fixture", 2)
    trials = [{"trial_id": name, "status": "missing"} for name in plan["trial_ids"]]
    bundle = build_study_bundle(plan, trials, {})
    assert bundle["sources"] == {}
    summary = verify_study_bundle(bundle)
    assert summary["security"]["observed_rate"] is None
    assert not summary["study_requirements_met"]


def test_builder_detaches_retained_sources_from_caller_mutation():
    source = next(iter(bundle_fixture()["sources"].values()))
    plan = build_study_plan(source, "fixture", 2)
    trials = [{"trial_id": name, "status": "complete", "evidence_sha256": source["evidence_sha256"]}
              for name in plan["trial_ids"]]
    bundle = build_study_bundle(plan, trials, dict.fromkeys(plan["trial_ids"], source))
    before = deepcopy(bundle)
    source["report"]["requirements_met"] = True
    plan["study_id"] = "changed"
    assert bundle == before
    assert verify_study_bundle(bundle)


def test_cli_relocation_replays_offline_without_any_original_source_path(tmp_path, monkeypatch):
    def offline(*args, **kwargs):
        pytest.fail("bundle operation attempted a network call")

    monkeypatch.setattr(socket.socket, "connect", offline)
    folder = tmp_path / "original"
    assert main(["study", "demo", "--out", str(folder)]) == 0
    output = tmp_path / "bundle.json"
    assert main(["study", "bundle", str(folder / "manifest.json"), "--out", str(output),
                 "--fail-on-shortfalls"]) == 1
    # Rename original files out of reach; verification must use only the bundle.
    folder.rename(tmp_path / "unavailable")
    assert main(["study", "verify-bundle", str(output)]) == 0
    assert main(["study", "verify-bundle", str(output), "--fail-on-shortfalls"]) == 1
    assert main(["study", "verify-bundle", str(output), "--expected-bundle-sha256", "0" * 64]) == 2
    page = tmp_path / "verified-review.html"
    assert main(["study", "verify-bundle", str(output), "--html", str(page), "--fail-on-shortfalls"]) == 1
    assert "3 / 5 trials complete" in page.read_text()
    previous = page.read_bytes()
    assert main(["study", "verify-bundle", str(output), "--html", str(page)]) == 2
    assert page.read_bytes() == previous


def test_cli_refuses_existing_output_invalid_sources_and_source_excerpt_leaks(tmp_path, capsys):
    folder = tmp_path / "demo"
    assert main(["study", "demo", "--out", str(folder)]) == 0
    destination = tmp_path / "keep.json"
    destination.write_text("keep")
    args = ["study", "bundle", str(folder / "manifest.json"), "--out", str(destination)]
    assert main(args) == 2
    assert destination.read_text() == "keep"
    (folder / "before.json").write_text('{"private-value":')
    args[-1] = str(tmp_path / "new.json")
    assert main(args) == 2
    assert not (tmp_path / "new.json").exists()
    assert "private-value" not in capsys.readouterr().err


def test_bundle_output_and_input_size_are_bounded(tmp_path, monkeypatch):
    folder = tmp_path / "demo"
    assert main(["study", "demo", "--out", str(folder)]) == 0
    output = tmp_path / "bundle.json"
    monkeypatch.setattr("dspy_security_bench.scan.study_bundle.MAX_BYTES", 1)
    assert main(["study", "bundle", str(folder / "manifest.json"), "--out", str(output)]) == 2
    assert not output.exists()
    output.write_text(json.dumps(bundle_fixture()))
    assert main(["study", "verify-bundle", str(output)]) == 2
