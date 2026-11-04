"""Bounded declarative checks for generated integration manifests and workflows."""

from __future__ import annotations

import re
import stat
from pathlib import Path

import yaml

from dspy_security_bench.integrations.catalog import get_framework
from dspy_security_bench.jsonio import read_json_object, read_regular_bytes
from dspy_security_bench.scan.yaml_config import ConfigLoader

MAX_CONTROL_BYTES = 1_000_000
WORKFLOW_PREFIX = "immu4989/dspy-security-bench/.github/workflows/proofrun.yml@"
FIELDS = {"schema_version", "framework", "agent", "model", "runner", "required_import",
          "required_env", "package_hint", "engine_ref"}
IMPORT = r"[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)*:[A-Za-z_]\w*"


def valid_target(value) -> bool:
    return isinstance(value, str) and len(value) <= 256 and re.fullmatch(IMPORT, value) is not None


def local_control_file(root: Path, relative: Path) -> Path:
    """Reject observed links/reparse points beneath a stable owner-selected root."""
    current = root.resolve(strict=True)
    for part in relative.parts:
        current = current / part
        info = current.lstat()
        if stat.S_ISLNK(info.st_mode) or getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0):
            raise ValueError("linked control input")
    return current


def read_manifest(root: Path, relative: Path) -> dict:
    manifest = read_json_object(local_control_file(root, relative), MAX_CONTROL_BYTES)
    if (set(manifest) != FIELDS or type(manifest["schema_version"]) is not int
            or manifest["schema_version"] != 1 or not isinstance(manifest["framework"], str)):
        raise ValueError("invalid integration envelope")
    spec = get_framework(manifest["framework"])
    if not valid_target(manifest["agent"]) or manifest["required_import"] != spec.import_name:
        raise ValueError("invalid integration import contract")
    for name in ("model", "package_hint"):
        value = manifest[name]
        if name == "model" and value is None:
            if spec.key != "mcp":
                raise ValueError("missing model")
        elif not isinstance(value, str) or not 1 <= len(value) <= 512 or not value.isprintable():
            raise ValueError("invalid metadata text")
    if (manifest["runner"] is not None and not valid_target(manifest["runner"])) or (spec.key == "mcp" and manifest["runner"] is None):
        raise ValueError("invalid callback target")
    keys = manifest["required_env"]
    if (not isinstance(keys, list) or len(keys) > 20
            or any(not isinstance(key, str) or re.fullmatch(r"[A-Z][A-Z0-9_]{0,127}", key) is None for key in keys)
            or len(set(keys)) != len(keys)):
        raise ValueError("invalid credential declarations")
    ref = manifest["engine_ref"]
    if (not isinstance(ref, str) or len(ref) > 100
            or re.fullmatch(r"(?:[a-f0-9]{40}|v[0-9]+\.[0-9]+\.[0-9]+(?:-[A-Za-z0-9][A-Za-z0-9.-]*)?)", ref) is None):
        raise ValueError("versioned or immutable engine reference required")
    return manifest


class WorkflowLoader(ConfigLoader):
    """Explicit bounded YAML subset; GitHub's `on` is a key, not YAML 1.1 true."""

    yaml_implicit_resolvers = {
        key: [(tag, pattern) for tag, pattern in values if tag != "tag:yaml.org,2002:bool"]
        for key, values in ConfigLoader.yaml_implicit_resolvers.items()
    }


WorkflowLoader.add_implicit_resolver("tag:yaml.org,2002:bool", re.compile(r"^(?:true|false|True|False|TRUE|FALSE)$"), list("tTfF"))


def inspect_workflow(root: Path, relative: Path, manifest: dict, target: str) -> list[str]:
    raw = read_regular_bytes(local_control_file(root, relative), MAX_CONTROL_BYTES)
    if len(raw) > MAX_CONTROL_BYTES:
        raise ValueError("workflow byte budget exceeded")
    try:
        workflow = yaml.load(raw.decode("utf-8"), Loader=WorkflowLoader)
    except (yaml.YAMLError, UnicodeError, RecursionError):
        raise ValueError("invalid bounded workflow YAML") from None
    if not isinstance(workflow, dict) or not isinstance(workflow.get("jobs"), dict):
        raise ValueError("workflow jobs required")
    jobs = [job for job in workflow["jobs"].values() if isinstance(job, dict)
            and isinstance(job.get("uses"), str) and job["uses"].startswith(WORKFLOW_PREFIX)]
    if len(jobs) != 1:
        return ["expected exactly one ProofRun reusable-workflow job"]
    job, problems = jobs[0], []
    if job["uses"] != WORKFLOW_PREFIX + manifest["engine_ref"]:
        problems.append("workflow engine reference does not match the manifest")
    if not isinstance(job.get("with"), dict) or job["with"].get("agent") != target:
        problems.append("workflow agent does not match the selected target")
    # Job-level permissions replace defaults; comments and unrelated jobs confer
    # no permission on this call. This is local configuration, not a hosted check.
    permissions = job.get("permissions", workflow.get("permissions"))
    if permissions != "write-all" and (not isinstance(permissions, dict)
            or any(permissions.get(key) != "write" for key in ("id-token", "attestations"))):
        problems.append("ProofRun job lacks explicit effective attestation permissions")
    if job.get("if") is False:
        problems.append("ProofRun job is explicitly disabled")
    return problems
