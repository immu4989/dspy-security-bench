"""`scan` — the CI gate: benchmark an agent, apply a pass/fail policy, report."""
from dspy_security_bench.scan.config import ScanConfig
from dspy_security_bench.scan.gate import Finding, ScanReport, evaluate_gate

__all__ = ["ScanConfig", "Finding", "ScanReport", "evaluate_gate"]
