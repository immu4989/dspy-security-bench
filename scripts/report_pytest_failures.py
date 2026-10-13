"""Expose bounded JUnit failure diagnostics on every CI platform.

Reads only the test report; does not upload artifacts or change the test verdict.
ASCII output keeps diagnostic rendering independent of the host console encoding.
"""

from __future__ import annotations

import sys
from pathlib import Path
from xml.etree import ElementTree

MAX_REPORT_BYTES = 20_000_000
MAX_FAILURES = 50
MAX_DETAIL_CHARACTERS = 8000


def escape(value: str, *, property_value: bool = False) -> str:
    value = value.encode("ascii", "backslashreplace").decode("ascii")
    value = value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")
    if property_value:
        value = value.replace(":", "%3A").replace(",", "%2C")
    return value


def report_failures(path: Path) -> None:
    try:
        with path.open("rb") as stream:
            source = stream.read(MAX_REPORT_BYTES + 1)
        if len(source) > MAX_REPORT_BYTES:
            raise ValueError("report too large")
        root = ElementTree.fromstring(source)
    except (OSError, ValueError, ElementTree.ParseError):
        print("::error title=pytest diagnostics::No readable bounded JUnit report; inspect the test step log.")
        return
    failures = root.findall(".//testcase[failure]") + root.findall(".//testcase[error]")
    for case in failures[:MAX_FAILURES]:
        problem = case.find("failure")
        if problem is None:
            problem = case.find("error")
        details = (problem.text or problem.get("message") or "pytest failure").strip()
        if len(details) > MAX_DETAIL_CHARACTERS:
            details = details[:MAX_DETAIL_CHARACTERS] + "\n[diagnostic truncated]"
        test_id = f"{case.get('classname', '')}.{case.get('name', '')}".strip(".")[:500]
        print(f"::error title={escape(test_id, property_value=True)}::{escape(details)}")
    if len(failures) > MAX_FAILURES:
        print(f"::warning::Additional failures omitted; {len(failures)} failing/error cases in the JUnit report.")


def main() -> int:
    if len(sys.argv) != 2:
        print("usage: report_pytest_failures.py REPORT.xml", file=sys.stderr)
        return 2
    report_failures(Path(sys.argv[1]))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
