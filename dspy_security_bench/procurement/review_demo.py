"""A credential-free teaching handoff built from synthetic reference execution."""

from __future__ import annotations

import json
from copy import deepcopy
from importlib.resources import files
from pathlib import Path

import yaml

from dspy_security_bench.policy import ToolPolicy
from dspy_security_bench.procurement.agents import (
    build_vulnerable_reference,
    synthetic_contracting_officer_approval,
)
from dspy_security_bench.procurement.control_registry import (
    create_control_submission_bundle,
    render_control_evidence_card_svg,
    verify_control_submission_bundle,
)
from dspy_security_bench.procurement.repeat import canonical_sha256
from dspy_security_bench.procurement.repeat_control import run_repeat_control_twin
from dspy_security_bench.procurement.sharing import create_sharing_review


def build_review_demo() -> dict[str, str]:
    """Run only bundled synthetic references, not a provider or arbitrary factory."""
    resource = files("dspy_security_bench.templates").joinpath("policies", "procurement.yaml")
    policy = ToolPolicy.from_dict(yaml.safe_load(resource.read_text(encoding="utf-8")))
    report = run_repeat_control_twin(
        build_vulnerable_reference, policy, trials=2, confidence_level=0.8,
        approval_handler=synthetic_contracting_officer_approval,
        approval_handler_label="deterministic synthetic contracting-officer fixture",
    ).to_dict()
    bundle = create_control_submission_bundle(
        report, submitter="synthetic-review-demo-not-a-supplier",
        agent_source_url="https://example.com/synthetic-reference-not-a-supplier",
        policy_source_url="https://example.com/synthetic-policy-not-a-deployment",
        notes="Teaching fixture only. No external model or production system was evaluated.",
    )
    reviewed = verify_control_submission_bundle(bundle)
    if not reviewed.valid or reviewed.registry_eligible:
        raise ValueError("synthetic teaching evidence must be valid but registry-ineligible")
    sharing = create_sharing_review(bundle)
    invalid = deepcopy(bundle)
    # Deliberately break a typed event, then recompute every enclosing hash.
    # This illustrates why hashing alone is weaker than native evidence replay.
    control = invalid["report"]["trials"][0]["control"]
    control["pairs"][0]["policy_events"][0]["index"] = False
    for value in (control, invalid["report"]):
        value.pop("report_sha256")
        value["report_sha256"] = canonical_sha256(value)
    invalid["report_sha256"] = canonical_sha256(invalid["report"])
    invalid.pop("bundle_sha256")
    invalid["bundle_sha256"] = canonical_sha256(invalid)
    if verify_control_submission_bundle(invalid).valid:
        raise ValueError("intentionally invalid teaching evidence was accepted")
    artifacts = {
        name: json.dumps(value, indent=2, sort_keys=True, allow_nan=False) + "\n"
        for name, value in (("report.json", report), ("bundle.json", bundle),
                            ("sharing-review.json", sharing), ("invalid-bundle.json", invalid))
    }
    artifacts["card.svg"] = render_control_evidence_card_svg(bundle)
    artifacts["README.md"] = """# Synthetic procurement evidence review

No external model, credentials, network calls, or production tools were used.
The bundled deterministic reference agent and synthetic approval callback were
executed on five frozen synthetic procurement pairs, twice, with an explicitly
selected 80% confidence level. This is a teaching fixture, not supplier evidence,
a government evaluation, certification, cost-saving estimate, or deployment approval.

Open card.svg in an SVG viewer. Its containment, recovery, and clean-preservation
metrics have separate conditional denominators; containment does not imply
mission recovery. Then replay these commands from this directory, one at a time:

```sh
dspy-security-bench impact control-repeat-verify report.json
dspy-security-bench impact control-submission-verify bundle.json
dspy-security-bench impact sharing-review bundle.json --verify sharing-review.json
dspy-security-bench impact control-submission-verify invalid-bundle.json
```

Expected exits are 0, 1, 0, 1. The second command prints NOT ELIGIBLE: the valid
reference fixture is not a public registry entry and has only two trials. The
fourth prints INVALID: an event index was replaced by false and every enclosing
hash was recomputed, but native verification still rejects the wrong type.
Do not treat every nonzero verification exit as the same problem, or chain
these teaching commands with `&&` and expect all four to run.

sharing-review.json inventories retained content without copying its text. It
always requires owner review; exit 0 is not permission to publish. Boundary
arguments and final answers can be present even when policy argument capture is
off. Inspect all original fields, including metadata and unknown extensions.

The sharing review binds the whole canonical bundle, including embedded digests.
Its source_sha256 is different from bundle_sha256. For a real handoff, retain a
source pin independently and supply --source-sha256 during replay. A pin copied
from an untrusted review does not establish independent trust. Digests do not
authenticate execution, redact content, or establish that declared outcomes are true.

Keep original evidence private where required. Replace this fixture with an
authorized test of your own adapter and synthetic data; do not submit these demo
files as measured community results. Do not point a demo at production write tools.

Each generation records elapsed time and producer metadata, so artifact hashes
may differ between runs. Replay the files from one generation together. The
output directory must be new and its parent must already exist. Existing files
are never overwritten; unexpected I/O failures may leave a partial directory for
inspection rather than deleting evidence.
"""
    return artifacts


def write_review_demo(destination: Path) -> None:
    if destination.exists() or destination.is_symlink() or not destination.parent.is_dir():
        raise ValueError("review demo needs a new directory beneath an existing parent")
    artifacts = build_review_demo()
    destination.mkdir(parents=False, exist_ok=False)
    for name, content in artifacts.items():
        with (destination / name).open("x", encoding="utf-8") as stream:
            stream.write(content)
