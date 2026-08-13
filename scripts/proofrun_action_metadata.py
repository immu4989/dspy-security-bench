#!/usr/bin/env python3
"""Export safe, scalar ProofRun fields to GitHub Actions outputs."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 2:
        raise SystemExit("usage: proofrun_action_metadata.py BUNDLE.json")
    payload = json.loads(Path(sys.argv[1]).read_text())
    resistance = payload["report"]["summary"]["attack_resistance"]
    values = {
        "bundle-sha256": payload["bundle_sha256"],
        "attack-resistance": resistance["rate"],
        "lower-bound": resistance["lower"],
    }
    output = os.environ.get("GITHUB_OUTPUT")
    if not output:
        raise SystemExit("GITHUB_OUTPUT is not set")
    with Path(output).open("a") as stream:
        for key, value in values.items():
            stream.write(f"{key}={value}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
