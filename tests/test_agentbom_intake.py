import json
from pathlib import Path

import pytest

from dspy_security_bench.supplychain.cli import main
from dspy_security_bench.supplychain.intake import PACK_FILES, verify_intake_pack, write_intake_pack

ROOT = Path(__file__).resolve().parents[1]
SOURCES = [
    ROOT / "examples" / name
    for name in ("ai-bom-disclosure-policy.json", "cyclonedx-mlbom-1.7.json", "spdx-ai-3.0.1.json")
]


def inputs():
    return [json.loads(path.read_text()) for path in SOURCES]


def test_intake_is_reproducible_and_retains_no_source_documents(tmp_path):
    first, second = tmp_path / "first", tmp_path / "second"
    manifest = write_intake_pack(first, *inputs())
    write_intake_pack(second, *inputs())
    assert manifest["finding_count"] == 4
    assert set(path.name for path in first.iterdir()) == set(PACK_FILES)
    for name in PACK_FILES:
        assert (first / name).read_bytes() == (second / name).read_bytes()
        assert b"private/model.bin" not in (first / name).read_bytes()
    assert verify_intake_pack(first, *inputs()) == ()
    with pytest.raises(FileExistsError):
        write_intake_pack(first, *inputs())


@pytest.mark.parametrize("mutation", ["extra", "edited", "symlink", "source"])
def test_intake_rejects_changes_to_pack_or_retained_inputs(tmp_path, mutation):
    pack = tmp_path / "review"
    data = inputs()
    write_intake_pack(pack, *data)
    if mutation == "extra":
        (pack / "undeclared.txt").write_text("unexpected")
    elif mutation == "edited":
        (pack / "review.md").write_text("Everything is approved")
    elif mutation == "symlink":
        path = pack / "review.md"
        path.rename(tmp_path / "original.md")
        path.symlink_to(tmp_path / "original.md")
    else:
        data[1]["metadata"]["component"]["name"] = "changed source"
    assert verify_intake_pack(pack, *data)


def test_intake_cli_gates_findings_and_verifies_all_artifacts(tmp_path):
    pack = tmp_path / "review"
    args = [
        "--policy",
        str(SOURCES[0]),
        "--cyclonedx-source",
        str(SOURCES[1]),
        "--spdx-source",
        str(SOURCES[2]),
    ]
    assert main(["intake-ai", *args, "--out-dir", str(pack), "--fail-on-findings"]) == 1
    assert main(["verify-ai-intake", str(pack), *args]) == 0
