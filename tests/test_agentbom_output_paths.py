from pathlib import Path

import pytest

from dspy_security_bench.supplychain.cli import main

ROOT = Path(__file__).resolve().parents[1]


@pytest.mark.parametrize("alias", ["same", "relative", "hardlink", "directory"])
def test_import_rejects_output_collisions_before_writing(tmp_path, alias):
    inventory = tmp_path / "inventory.json"
    inventory.write_text("keep original inventory")
    report = inventory
    if alias == "relative":
        report = tmp_path / "." / "inventory.json"
    elif alias == "hardlink":
        report = tmp_path / "report.json"
        report.hardlink_to(inventory)
    elif alias == "directory":
        report = tmp_path / "reports"
        report.mkdir()
    result = main(
        [
            "import-mlbom",
            str(ROOT / "examples/cyclonedx-mlbom-1.7.json"),
            "--inventory-id",
            "output-safety",
            "--out",
            str(inventory),
            "--report-out",
            str(report),
            "--force",
        ]
    )
    assert result == 2
    assert inventory.read_text() == "keep original inventory"
