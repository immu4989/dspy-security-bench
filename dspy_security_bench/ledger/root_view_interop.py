"""Portable cross-implementation evidence for RootViewQuorum vectors."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping
from copy import deepcopy
from pathlib import Path
from typing import Any

from dspy_security_bench.ledger.root_view_vectors import (
    EXPECTED_CASE_IDS,
    EXPECTED_MANIFEST_SHA256,
    MANIFEST_FILE,
    MAX_VECTOR_FILE_BYTES,
    VECTOR_VERSION,
    verify_root_view_vector_pack,
)
from dspy_security_bench.mission.loader import canonical_sha256

REPORT_TYPE = (
    "AssuranceLedger RootViewInteropEvidence / Cross-implementation known-answer agreement"
)
PROTOCOL_VERSION = "assuranceledger-root-view-interop-evidence-v1"
PREDICATE_TYPE = (
    "https://immu4989.github.io/dspy-security-bench/attestations/root-view-interop-evidence/v1"
)
STATEMENT_TYPE = "https://in-toto.io/Statement/v1"
REFERENCE_IMPLEMENTATION = "dspy-security-bench-root-view-python-v1"
ANALYZER = "deterministic-root-view-interoperability-analyzer-v1"
MAX_RESULT_BYTES = 2_000_000
MAX_SOURCE_BYTES = 2_000_000
_IMPLEMENTATION_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$")
_LANGUAGE = re.compile(r"^[a-z][a-z0-9+.-]{0,49}$")
_RESULT_FIELDS = {
    "implementation",
    "implementation_sha256",
    "runtime",
    "vector_version",
    "manifest_sha256",
    "cases",
    "summary",
}
_CASE_FIELDS = {
    "case_id",
    "status",
    "expected_status",
    "observed_status",
    "verifier_accepted",
}
CLAIM_BOUNDARY = (
    "RootViewInteropEvidence records exact agreement between the local Python reference "
    "verifier and one separately supplied implementation result for the immutable "
    "RootViewQuorum v1 known-answer corpus, while binding the corpus manifest and exact "
    "verifier source bytes. interoperability_observed means only that the supplied result "
    "matches all eight finite expected decisions. It is not proof that the bound external "
    "source executed, general conformance, independent assessment, cryptographic-module "
    "validation, certification, government endorsement, deployment approval, or an ATO."
)
LIMITATIONS = (
    "The external implementation result is self-reported; its source digest binds bytes but does not establish which code a runner executed.",
    "Execution identity, runner isolation, invocation parameters, and artifact delivery require separately verified CI provenance or signed attestations.",
    "Both implementations are evaluated only against the same finite public corpus and may share specification misunderstandings.",
    "The embedded in-toto Statement is unsigned and attestation-ready; a deployment must authenticate it through its own trusted envelope and identity policy.",
    "The analyzer performs no network access, root installation, deployment, notification, revocation, or automatic remediation.",
)


def build_root_view_interop_report(
    pack_dir: str | Path,
    implementation_result: Mapping[str, Any],
    implementation_source: str | Path,
    *,
    implementation_language: str,
) -> dict[str, Any]:
    """Bind a successful external vector run to its source and the local reference."""

    pack = Path(pack_dir)
    if errors := verify_root_view_vector_pack(pack):
        raise ValueError("RootViewQuorum vector pack is not verified: " + "; ".join(errors))
    manifest = _read_json(pack / MANIFEST_FILE, MAX_RESULT_BYTES)
    manifest_file_sha256 = hashlib.sha256((pack / MANIFEST_FILE).read_bytes()).hexdigest()
    source = Path(implementation_source)
    if source.resolve() in {
        (Path(__file__).resolve().parent / "root_view.py").resolve(),
        (Path(__file__).resolve().parent / "root_view_vectors.py").resolve(),
    }:
        raise ValueError("external implementation source must be separate from the reference")
    source_bytes = _read_regular_bytes(source, MAX_SOURCE_BYTES, "implementation source")
    source_sha256 = hashlib.sha256(source_bytes).hexdigest()
    _validate_implementation_result(implementation_result, manifest, source_sha256)
    if not isinstance(implementation_language, str) or not _LANGUAGE.fullmatch(
        implementation_language
    ):
        raise ValueError("implementation_language must be a lowercase language identifier")

    reference_sources = _reference_source_descriptors()
    external_id = implementation_result["implementation"]
    if external_id == REFERENCE_IMPLEMENTATION:
        raise ValueError("external implementation ID must differ from the reference")
    external_source = {
        "name": f"implementation/{external_id}/{source.name}",
        "sha256": source_sha256,
    }
    agreements = _case_agreements(pack, manifest, implementation_result)
    if not all(item["agreement"] for item in agreements):
        raise ValueError("external implementation result disagrees with the reference corpus")
    statement = {
        "_type": STATEMENT_TYPE,
        "subject": [
            {
                "name": "root-view-quorum-v1/vector-manifest.json",
                "digest": {"sha256": manifest_file_sha256},
            },
            *(
                {"name": item["name"], "digest": {"sha256": item["sha256"]}}
                for item in reference_sources
            ),
            {
                "name": external_source["name"],
                "digest": {"sha256": external_source["sha256"]},
            },
        ],
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "analyzer": ANALYZER,
            "vector_version": VECTOR_VERSION,
            "manifest_sha256": EXPECTED_MANIFEST_SHA256,
            "implementations": [
                {
                    "implementation_id": REFERENCE_IMPLEMENTATION,
                    "language": "python",
                    "source_files": reference_sources,
                },
                {
                    "implementation_id": external_id,
                    "language": implementation_language,
                    "runtime": implementation_result["runtime"],
                    "source_files": [external_source],
                },
            ],
            "implementation_result": deepcopy(dict(implementation_result)),
            "case_agreements": agreements,
            "summary": {
                "status": "interoperability_observed",
                "implementation_count": 2,
                "case_count": len(agreements),
                "agreement_count": sum(item["agreement"] for item in agreements),
                "disagreement_count": sum(not item["agreement"] for item in agreements),
                "automatic_actions": 0,
            },
        },
    }
    report: dict[str, Any] = {
        "schema_version": 1,
        "report_type": REPORT_TYPE,
        "protocol_version": PROTOCOL_VERSION,
        "statement": statement,
        "claim_boundary": CLAIM_BOUNDARY,
        "limitations": list(LIMITATIONS),
    }
    report["report_sha256"] = canonical_sha256(report)
    return report


def verify_root_view_interop_report(
    report: Mapping[str, Any],
    pack_dir: str | Path,
    implementation_source: str | Path,
) -> tuple[str, ...]:
    """Recompute a saved interop report against retained corpus and source bytes."""

    if not isinstance(report, Mapping):
        return ("report must be an object",)
    errors: list[str] = []
    if (
        report.get("report_type") != REPORT_TYPE
        or report.get("protocol_version") != PROTOCOL_VERSION
    ):
        errors.append("unsupported AssuranceLedger RootViewInteropEvidence")
    unsigned = dict(report)
    claimed = unsigned.pop("report_sha256", None)
    try:
        if claimed != canonical_sha256(unsigned):
            errors.append("report_sha256 does not recompute")
    except (TypeError, ValueError):
        errors.append("report is not canonical JSON data")
    try:
        statement = report["statement"]
        predicate = statement["predicate"]
        implementations = predicate["implementations"]
        external = implementations[1]
        expected = build_root_view_interop_report(
            pack_dir,
            predicate["implementation_result"],
            implementation_source,
            implementation_language=external["language"],
        )
    except (IndexError, KeyError, OSError, TypeError, ValueError) as exc:
        errors.append(f"RootViewInteropEvidence cannot recompute: {exc}")
    else:
        if report != expected:
            errors.append("RootViewInteropEvidence does not recompute exactly")
    return tuple(dict.fromkeys(errors))


def load_implementation_result(path: str | Path) -> dict[str, Any]:
    """Read a bounded external implementation result for CLI consumers."""

    return _read_json(Path(path), MAX_RESULT_BYTES)


def _case_agreements(
    pack: Path,
    manifest: Mapping[str, Any],
    result: Mapping[str, Any],
) -> list[dict[str, Any]]:
    rows = []
    for expected, observed in zip(manifest["cases"], result["cases"], strict=True):
        report = _read_json(pack / expected["report_file"], MAX_VECTOR_FILE_BYTES)
        reference_status = report.get("summary", {}).get("status")
        agreement = (
            observed["status"] == "passed"
            and observed["expected_status"] == expected["expected_status"]
            and observed["observed_status"] == reference_status
            and observed["verifier_accepted"] == expected["expected_verifier_acceptance"]
        )
        rows.append(
            {
                "case_id": expected["case_id"],
                "operation": expected["operation"],
                "expected_status": expected["expected_status"],
                "reference_observed_status": reference_status,
                "external_observed_status": observed["observed_status"],
                "expected_verifier_acceptance": expected["expected_verifier_acceptance"],
                "reference_verifier_accepted": expected["expected_verifier_acceptance"],
                "external_verifier_accepted": observed["verifier_accepted"],
                "agreement": agreement,
            }
        )
    return rows


def _validate_implementation_result(
    result: Mapping[str, Any], manifest: Mapping[str, Any], source_sha256: str
) -> None:
    if not isinstance(result, Mapping) or set(result) != _RESULT_FIELDS:
        raise ValueError("implementation result fields are not exact")
    implementation = result.get("implementation")
    if not isinstance(implementation, str) or not _IMPLEMENTATION_ID.fullmatch(implementation):
        raise ValueError("implementation result has an invalid implementation ID")
    if result.get("implementation_sha256") != source_sha256:
        raise ValueError("implementation result does not bind the supplied source bytes")
    runtime = result.get("runtime")
    if not isinstance(runtime, str) or not runtime or len(runtime) > 200:
        raise ValueError("implementation result has an invalid runtime")
    if result.get("vector_version") != VECTOR_VERSION:
        raise ValueError("implementation result has the wrong vector version")
    if result.get("manifest_sha256") != EXPECTED_MANIFEST_SHA256:
        raise ValueError("implementation result has the wrong manifest digest")
    cases = result.get("cases")
    if not isinstance(cases, list) or len(cases) != len(EXPECTED_CASE_IDS):
        raise ValueError("implementation result must contain all eight vector cases")
    for index, (case, expected) in enumerate(zip(cases, manifest["cases"], strict=True)):
        if not isinstance(case, Mapping) or set(case) != _CASE_FIELDS:
            raise ValueError(f"implementation result case {index} fields are not exact")
        if case.get("case_id") != expected["case_id"]:
            raise ValueError(f"implementation result case {index} is out of order")
        if case.get("status") != "passed":
            raise ValueError(f"implementation result case {expected['case_id']} did not pass")
        if case.get("expected_status") != expected["expected_status"]:
            raise ValueError(
                f"implementation result case {expected['case_id']} changed the expectation"
            )
        if not isinstance(case.get("verifier_accepted"), bool):
            raise ValueError(
                f"implementation result case {expected['case_id']} has an invalid decision"
            )
    expected_summary = {
        "passed": len(EXPECTED_CASE_IDS),
        "failed": 0,
        "automatic_actions": 0,
    }
    if result.get("summary") != expected_summary:
        raise ValueError("implementation result summary is not an exact successful run")


def _reference_source_descriptors() -> list[dict[str, str]]:
    module_root = Path(__file__).resolve().parent
    descriptors = []
    for name in ("root_view.py", "root_view_vectors.py"):
        raw = _read_regular_bytes(module_root / name, MAX_SOURCE_BYTES, name)
        descriptors.append(
            {
                "name": f"dspy_security_bench/ledger/{name}",
                "sha256": hashlib.sha256(raw).hexdigest(),
            }
        )
    return descriptors


def _read_json(path: Path, limit: int) -> dict[str, Any]:
    raw = _read_regular_bytes(path, limit, "JSON input")
    value = json.loads(raw)
    if not isinstance(value, dict):
        raise ValueError(f"{path} must contain a JSON object")
    return value


def _read_regular_bytes(path: Path, limit: int, label: str) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError(f"{label} must be a regular non-symbolic-link file")
    if path.stat().st_size > limit:
        raise ValueError(f"{label} exceeds {limit} bytes")
    return path.read_bytes()
