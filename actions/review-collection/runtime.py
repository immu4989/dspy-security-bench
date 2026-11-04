"""Install this action's locked runtime in a fresh runner-temporary environment.

Only the trusted action source is built. This is dependency isolation, not a
sandbox or a claim about the trustworthiness of Python, uv, or build backends.
"""

from __future__ import annotations

import hashlib
import os
import stat
import subprocess
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# Cache/interpreter locations and explicit network denial are runner controls,
# not dependency-selection or synchronization overrides from the caller job.
UV_RUNNER_CONTROLS = {"UV_CACHE_DIR", "UV_PYTHON_INSTALL_DIR", "UV_OFFLINE", "UV_PYTHON_DOWNLOADS"}


def prepare(environment, root: Path = ROOT) -> dict[str, str]:
    temporary = environment.get("RUNNER_TEMP", "")
    if (environment.get("RUNNER_OS") != "Linux" or not temporary
            or not Path(temporary).is_absolute()
            or any(ord(c) < 32 or ord(c) == 127 for c in temporary)
            or any(c in temporary for c in "*?[]!")):
        raise ValueError("unsupported runner environment")
    parent = Path(temporary)
    for path in (parent, *parent.parents):
        info = path.lstat()
        if not stat.S_ISDIR(info.st_mode):
            raise ValueError("stable unlinked runner directory required")
    # No caller-directory discovery, active venv, or editable source import.
    sources = {name: (root / name).read_bytes() for name in ("uv.lock", "pyproject.toml")}
    runtime = Path(tempfile.mkdtemp(prefix="proofrun-runtime-", dir=parent)) / "venv"
    env = {key: value for key, value in environment.items()
           if key not in {"VIRTUAL_ENV", "PYTHONPATH", "PYTHONHOME"}
           and (not key.startswith("UV_") or key in UV_RUNNER_CONTROLS)}
    env["UV_PROJECT_ENVIRONMENT"] = str(runtime)
    subprocess.run(
        ["uv", "--no-config", "sync", "--locked", "--no-default-groups", "--no-dev", "--no-editable",
         "--python", "3.12", "--project", str(root)],
        env=env, stdin=subprocess.DEVNULL, check=True, timeout=600,
    )
    if any((root / name).read_bytes() != raw for name, raw in sources.items()):
        raise ValueError("runtime source inputs changed")
    python = runtime / "bin/python"
    if not python.is_file():
        raise ValueError("review interpreter missing")
    return {"python": str(python), "dependency-lock-sha256": hashlib.sha256(sources["uv.lock"]).hexdigest()}


def main() -> int:
    try:
        outputs = prepare(os.environ)
        with Path(os.environ["GITHUB_OUTPUT"]).open("a", encoding="utf-8", newline="\n") as stream:
            stream.write("".join(f"{key}={value}\n" for key, value in outputs.items()))
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("ProofRun runtime setup failed; no ready reviewer was published. Inspect setup logs and partial runner-temporary output.", file=sys.stderr)
        return 2
    print("ProofRun reviewer installed from the action's unchanged lockfile in a fresh environment.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
