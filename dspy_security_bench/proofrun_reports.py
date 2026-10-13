"""One fresh native decision, three synchronized source-redacted presentations."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from dspy_security_bench.outputio import check_directory, check_new_directory, write_new_file
from dspy_security_bench.proofrun_collection import review_collection
from dspy_security_bench.proofrun_html import render_collection_html, render_review_html
from dspy_security_bench.proofrun_junit import render_collection_junit, render_review_junit
from dspy_security_bench.proofrun_review import ReviewPolicy, review_bundle

REASONS = {
    "exported": "All report formats were written from one fresh decision; inspect the native exit code.",
    "invalid_output": "Report destination must be a new directory under an existing unlinked parent; review was not run.",
    "review_error": "Native review could not be completed; source diagnostics withheld and no report directory created.",
    "render_error": "Report rendering failed; no report directory was created. Native outcome, if available, is retained.",
    "output_error": "Report set could not be completed; inspect the new directory for partial files. Existing destinations are never overwritten.",
}


def _json(value: dict) -> bytes:
    return (json.dumps(value, sort_keys=True, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")


def _export(output, evaluate, *, collection, scope):
    receipt = {
        "schema_version": 1, "receipt_type": "ProofRun report set export",
        "native_exit_code": None, "review_file_sha256": None, "manifest_file_sha256": None,
        "files_written": 0, "report_set_complete": False,
        "review_is_attestation": False, "execution_reproduced": False,
    }

    def finish(reason):
        return {**receipt, "reason_code": reason,
                "exit_code": receipt["native_exit_code"] if reason == "exported" else 2}

    try:
        output = check_new_directory(Path(output))
    except (OSError, TypeError, ValueError):
        return finish("invalid_output")
    try:
        review = evaluate()
        code = review["exit_code"]
        if type(code) is not int or code not in (0, 1, 2):
            raise ValueError("unexpected native decision")
        receipt["native_exit_code"] = code
    except Exception:
        # Unexpected implementation errors must not leak source diagnostics or
        # be converted into a successful review. Interrupts still propagate.
        return finish("review_error")
    try:
        html = render_collection_html if collection else render_review_html
        junit = render_collection_junit if collection else render_review_junit
        documents = {
            "review.json": _json(review),
            "review.html": (html(review) + "\n").encode("utf-8"),
            "review.xml": (junit(review, scope=scope) + "\n").encode("utf-8"),
        }
        receipt["review_file_sha256"] = hashlib.sha256(documents["review.json"]).hexdigest()
        manifest = {
            "schema_version": 1, "report_type": "ProofRun report set",
            "review_type": review["review_type"], "verifier_version": review["verifier_version"],
            "native_exit_code": code, "review_is_attestation": False, "execution_reproduced": False,
            "files": [{"path": name, "sha256": hashlib.sha256(raw).hexdigest(), "size_bytes": len(raw)}
                      for name, raw in documents.items()],
        }
        documents["manifest.json"] = _json(manifest)
    except Exception:
        return finish("render_error")
    try:
        check_new_directory(output)
        output.mkdir(mode=0o700, parents=False, exist_ok=False)
        for name, raw in documents.items():
            check_directory(output)
            write_new_file(output / name, raw)
            receipt["files_written"] += 1
    except (OSError, TypeError, ValueError):
        return finish("output_error")
    receipt["manifest_file_sha256"] = hashlib.sha256(documents["manifest.json"]).hexdigest()
    receipt["report_set_complete"] = True
    return finish("exported")


def export_bundle_reports(path: Path, output: Path, *, policy: ReviewPolicy | None = None) -> dict:
    """Verify an original artifact once and export all three formats.

    This does not read or authenticate a saved review. A successful export can
    contain an unsuccessful native verdict: the CLI preserves its 0/1/2 code.
    Local exclusive creation requires stable owner-controlled parents and is
    not an atomic/durable multi-file transaction or filesystem sandbox.
    """
    return _export(output, lambda: review_bundle(path, policy=policy), collection=False, scope=str(path))


def export_collection_reports(path: Path, output: Path, *, expected_plan_file_sha256: str | None = None) -> dict:
    """Review a required collection once, including missing and invalid outcomes."""
    return _export(output, lambda: review_collection(path, expected_plan_file_sha256=expected_plan_file_sha256),
                   collection=True, scope=str(path))
