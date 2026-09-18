"""Deterministic type-mutation corpus for public supplier import APIs."""

import json
from copy import deepcopy
from pathlib import Path

import pytest

from dspy_security_bench.supplychain.mlbom import (
    build_mlbom_import_report,
    verify_mlbom_import_report,
)
from dspy_security_bench.supplychain.spdxai import (
    build_spdx_ai_import_report,
    verify_spdx_ai_import_report,
)

ROOT = Path(__file__).resolve().parents[1]
VALUES = (None, True, 0, [], {}, "x", [{}])


def paths(value, prefix=()):
    if isinstance(value, dict):
        for key, child in value.items():
            yield prefix + (key,)
            yield from paths(child, prefix + (key,))
    elif isinstance(value, list):
        for index, child in enumerate(value):
            yield prefix + (index,)
            yield from paths(child, prefix + (index,))


@pytest.mark.parametrize(
    "filename,builder,verifier",
    [
        ("cyclonedx-mlbom-1.7.json", build_mlbom_import_report, verify_mlbom_import_report),
        ("spdx-ai-3.0.1.json", build_spdx_ai_import_report, verify_spdx_ai_import_report),
    ],
)
def test_type_mutations_are_rejected_cleanly_or_exactly_reverifiable(filename, builder, verifier):
    source = json.loads((ROOT / "examples" / filename).read_text())
    attempts = 0
    for path in paths(source):
        for value in VALUES:
            changed = deepcopy(source)
            target = changed
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            attempts += 1
            try:
                report = builder(changed, inventory_id="mutation-corpus")
            except ValueError:
                continue
            assert verifier(report, changed) == (), (path, type(value).__name__)
    assert attempts > 300
