"""Pre-sharing inventory is complete, content-free, source-bound, and non-mutating."""

import json
from copy import deepcopy

import pytest

from dspy_security_bench.procurement.agents import ReferenceProcurementAgent
from dspy_security_bench.procurement.cli import main
from dspy_security_bench.procurement.repeat import canonical_sha256, run_repeat_twin
from dspy_security_bench.procurement.sharing import create_sharing_review, verify_sharing_review


@pytest.fixture(scope="module")
def report():
    return run_repeat_twin(ReferenceProcurementAgent(vulnerable=False), trials=2).to_dict()


def test_inventory_never_copies_private_values_or_keys(report):
    source = deepcopy(report)
    source["trials"][0]["pairs"][0]["clean"]["final_answer"] = "PRIVATE-ANSWER-é"
    source["PRIVATE-EXTENSION"] = {"PRIVATE-KEY": ["PRIVATE-VALUE", 42, None, False, {}]}
    original = deepcopy(source)
    review = create_sharing_review(source)
    assert source == original
    assert "PRIVATE" not in json.dumps(review)
    assert review["source_sha256"] == canonical_sha256(source)
    assert review["publication_status"] == "owner_review_required"
    assert review["inventory"]["model_outputs"]["nonempty_strings"] > 0
    verify_sharing_review(review, source)


def test_every_key_and_leaf_is_counted_including_unknown_extensions(report):
    source = deepcopy(report)
    source["extension"] = {"é": ["é", "", 42, None, True, {}, []]}
    totals = {name: 0 for name in create_sharing_review(source)["inventory"]["other_content"]}

    def count(value):
        if isinstance(value, dict):
            totals["objects"] += 1
            for key, child in value.items():
                totals["object_keys"] += 1
                totals["key_utf8_bytes"] += len(key.encode())
                count(child)
        elif isinstance(value, list):
            totals["arrays"] += 1
            for child in value:
                count(child)
        elif isinstance(value, str):
            totals["string_values"] += 1
            totals["nonempty_strings"] += bool(value)
            totals["string_utf8_bytes"] += len(value.encode())
        else:
            totals["nonstring_values"] += 1

    count(source)
    inventory = create_sharing_review(source)["inventory"]
    assert totals == {key: sum(row[key] for row in inventory.values()) for key in totals}


@pytest.mark.parametrize("pin", ["0" * 64, "BAD", True, 42, "A" * 64])
def test_independent_pins_reject_mismatch(report, pin):
    with pytest.raises(ValueError, match="pin"):
        create_sharing_review(report, source_sha256=pin)


def test_rehashed_review_cannot_authorize_publication_or_hide_content(report):
    review = create_sharing_review(report, source_sha256=canonical_sha256(report))
    for key, value in [("publication_status", "safe"), ("inventory", {}), ("schema_version", True)]:
        changed = {**review, key: value}
        changed.pop("review_sha256")
        changed["review_sha256"] = canonical_sha256(changed)
        with pytest.raises(ValueError, match="replay"):
            verify_sharing_review(changed, report)


def test_changed_source_with_identical_counts_still_fails_replay(report):
    source = deepcopy(report)
    source["extra"] = "AAA"
    review = create_sharing_review(source)
    source["extra"] = "BBB"
    with pytest.raises(ValueError, match="replay"):
        verify_sharing_review(review, source)


def test_invalid_evidence_not_inventoried_and_errors_are_redacted(report):
    source = deepcopy(report)
    source["trials"][0]["pairs"][0]["clean"]["expected_proposal"] = "PRIVATE"
    with pytest.raises(ValueError, match="native") as caught:
        create_sharing_review(source)
    assert "PRIVATE" not in str(caught.value)


def test_offline_cli_roundtrip_no_overwrite_and_no_source_mutation(report, tmp_path, monkeypatch):
    import socket

    def forbidden(*args, **kwargs):
        pytest.fail("review must not execute models or connect to the network")

    monkeypatch.setattr(socket.socket, "connect", forbidden)
    monkeypatch.setattr(ReferenceProcurementAgent, "run", forbidden)
    source = tmp_path / "source.json"
    output = tmp_path / "review.json"
    source.write_text(json.dumps(report))
    original = source.read_bytes()
    assert main(["sharing-review", str(source), "--out", str(output)]) == 0
    saved = output.read_bytes()
    assert main(["sharing-review", str(source), "--verify", str(output)]) == 0
    assert main(["sharing-review", str(source), "--out", str(output)]) == 2
    assert main(["sharing-review", str(source), "--out", str(source)]) == 2
    assert source.read_bytes() == original
    assert output.read_bytes() == saved


def test_sharing_review_rejects_dangling_output_without_creating_target(report, tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report))
    output, target = tmp_path / "linked.json", tmp_path / "absent.json"
    try:
        output.symlink_to(target)
    except OSError:
        pytest.skip("symlink creation unavailable")
    assert main(["sharing-review", str(source), "--out", str(output)]) == 2
    assert output.is_symlink() and not target.exists()


@pytest.mark.parametrize("raw", ['{"agent":1,"agent":2}', '{"x":NaN}', '{"x":"\\ud800"}', '[]'])
def test_cli_strict_intake(raw, tmp_path, capsys):
    source = tmp_path / "PRIVATE.json"
    output = tmp_path / "out.json"
    source.write_text(raw)
    assert main(["sharing-review", str(source), "--out", str(output)]) == 2
    assert not output.exists()
    assert "PRIVATE" not in capsys.readouterr().err


def test_all_supported_native_formats_and_ineligible_bundles(report):
    from dspy_security_bench.procurement.agents import build_vulnerable_reference
    from dspy_security_bench.procurement.control_registry import create_control_submission_bundle
    from dspy_security_bench.procurement.control_twin import run_control_twin
    from dspy_security_bench.procurement.repeat import create_submission_bundle
    from dspy_security_bench.procurement.repeat_control import run_repeat_control_twin
    from tests.test_control_twin import _procurement_policy

    metadata = {"submitter": "PRIVATE-SUBMITTER", "agent_source_url": "https://example.com/PRIVATE"}
    repeat_bundle = create_submission_bundle(report, **metadata)
    control = run_control_twin(build_vulnerable_reference, _procurement_policy()).to_dict()
    repeated = run_repeat_control_twin(
        build_vulnerable_reference, _procurement_policy(), trials=2,
    ).to_dict()
    control_bundle = create_control_submission_bundle(
        repeated, **metadata, policy_source_url="https://example.com/PRIVATE-policy",
    )
    for source, kind in [
        (report, "repeat_report"), (repeat_bundle, "repeat_submission"),
        (control, "control_report"), (repeated, "repeat_control_report"),
        (control_bundle, "control_submission"),
    ]:
        original = deepcopy(source)
        review = create_sharing_review(source)
        assert review["source_kind"] == kind
        assert "PRIVATE" not in json.dumps(review)
        verify_sharing_review(review, source)
        assert source == original
        if "bundle_type" in source:
            assert review["inventory"]["submission_metadata"]["nonempty_strings"] > 0
            source["report_sha256"] = "0" * 64
            with pytest.raises(ValueError, match="native"):
                create_sharing_review(source)


@pytest.mark.parametrize("source", [{}, [], {"bundle_type": []}, {"x": float("inf")}])
def test_unknown_or_nonportable_sources_are_rejected(source):
    with pytest.raises(ValueError):
        create_sharing_review(source)


def test_bounded_input(report, monkeypatch):
    monkeypatch.setattr("dspy_security_bench.procurement.sharing.MAX_SHARING_BYTES", 10)
    with pytest.raises(ValueError, match="bounded"):
        create_sharing_review(report)


def test_cli_wrong_pin_and_symlink_leave_files_untouched(report, tmp_path):
    source = tmp_path / "source.json"
    source.write_text(json.dumps(report))
    output = tmp_path / "out.json"
    assert main([
        "sharing-review", str(source), "--out", str(output), "--source-sha256", "0" * 64,
    ]) == 2
    assert not output.exists()
    output.symlink_to(source)
    original = source.read_bytes()
    assert main(["sharing-review", str(source), "--out", str(output)]) == 2
    assert source.read_bytes() == original
