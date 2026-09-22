"""Renderers for a `ScanReport`: terminal, JSON, and SARIF.

SARIF is the format GitHub code scanning ingests, so findings surface natively
in a PR's Security tab. Each failing cell becomes one result under a single
rule mapped to OWASP LLM01 (Prompt Injection), with NIST AI 100-2 and MITRE
ATLAS references in the rule's property bag.
"""
from __future__ import annotations

import json
from pathlib import Path

from dspy_security_bench.scan.gate import ScanReport

# Tool / standards metadata. IDs verified against the public taxonomies; the
# property bag is the extension point if a program needs additional mappings.
RULE_ID = "dspy-security-bench/LLM01-prompt-injection"
COVERAGE_RULE_ID = "dspy-security-bench/missing-baseline-coverage"
SAMPLE_RULE_ID = "dspy-security-bench/insufficient-sample-coverage"
UNCERTAINTY_RULE_ID = "dspy-security-bench/uncertainty-threshold"
UTILITY_RULE_ID = "dspy-security-bench/task-utility-threshold"
OWASP_URI = "https://genai.owasp.org/llmrisk/llm01-prompt-injection/"
STANDARDS = {
    "OWASP-LLM-Top-10-2025": "LLM01: Prompt Injection",
    "NIST-AI-100-2e2025": "Direct & indirect prompt injection (adversarial ML taxonomy)",
    "MITRE-ATLAS": "AML.T0051 LLM Prompt Injection",
}

_SARIF_LEVEL = {"error": "error", "warning": "warning", "none": "note"}


# ---------------------------------------------------------------------------
# Terminal
# ---------------------------------------------------------------------------

def render_terminal(report: ScanReport, use_color: bool = True) -> str:
    def c(code: str, s: str) -> str:
        return f"\033[{code}m{s}\033[0m" if use_color else s

    lines = []
    lines.append("=" * 78)
    lines.append(f" dspy-security-bench scan — gate: {report.mode}")
    lines.append("=" * 78)
    header = f" {'':1} {'agent':<22} {'defense':<14} {'attack':<22} {'security':>9}"
    lines.append(header)
    lines.append(" " + "-" * 74)
    for f in report.findings:
        mark = c("32", "✓") if f.passed else (c("33", "▲") if f.severity == "warning" else c("31", "✗"))
        base = f"  (base {f.baseline_security:.0%})" if f.baseline_security is not None else ""
        row = f" {mark} {f.agent[:22]:<22} {f.defense[:14]:<14} {f.attack[:22]:<22} {f.security_rate:>8.0%}{base}"
        lines.append(row)
        if f.utility_rate is not None:
            lines.append(f"    task utility under attack={f.utility_rate:.2%}; point-rate floor={f.threshold:.2%}")
        if f.security_lower is not None:
            lines.append(f"    n={f.n_runs}; {f.confidence:.2%} Wilson [{f.security_lower:.2%}, {f.security_upper:.2%}]")
    lines.append(" " + "-" * 74)
    for f in report.findings:
        if not f.passed:
            tag = c("33", "WARN") if f.severity == "warning" else c("31", "FAIL")
            lines.append(f"  [{tag}] {f.message}")
    if report.enforcement_status == "non_blocking_shortfalls":
        verdict = c("33;1", "NON-BLOCKING SHORTFALLS")
    else:
        verdict = c("32;1", "PASS") if report.passed else c("31;1", "FAIL")
    lines.append("")
    lines.append(f" Verdict: {verdict}  (exit {report.exit_code})")
    lines.append(f" Requirements met: {'yes' if report.requirements_met else 'no'}; enforcement: {report.meta.get('fail_on', 'unspecified')}")
    lines.append("")
    lines.append(" " + report.disclaimer)
    if report.meta.get("uncertainty_boundary"):
        lines.append(" " + report.meta["uncertainty_boundary"])
    lines.append("=" * 78)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2, allow_nan=False)


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

def render_sarif(report: ScanReport, config_path: str = ".dspy-security-bench.yaml") -> str:
    results = []
    for f in report.findings:
        if f.passed:
            continue  # only surface failures in the Security tab
        results.append({
            "ruleId": {"baseline_coverage": COVERAGE_RULE_ID, "sample_coverage": SAMPLE_RULE_ID,
                       "uncertainty_threshold": UNCERTAINTY_RULE_ID,
                       "utility_threshold": UTILITY_RULE_ID}.get(f.finding_type, RULE_ID),
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": config_path},
                    "region": {"startLine": 1},
                }
            }],
            "properties": {
                "suite": f.suite, "agent": f.agent, "defense": f.defense,
                "attack": f.attack, "security_rate": f.security_rate,
                "injection_success_rate": f.injection_success_rate,
                "n_runs": f.n_runs,
                "security_successes": f.security_successes,
                "security_lower": f.security_lower, "security_upper": f.security_upper,
                "confidence": f.confidence, "required_runs": f.required_runs,
                **({"utility_rate": f.utility_rate} if f.utility_rate is not None else {}),
            },
        })

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {"driver": {
                "name": "dspy-security-bench",
                "informationUri": "https://github.com/immu4989/dspy-security-bench",
                "rules": [{
                    "id": RULE_ID,
                    "name": "PromptInjection",
                    "shortDescription": {"text": "Agent followed injected instructions"},
                    "fullDescription": {"text":
                        "The agent executed instructions embedded in untrusted tool "
                        "output (prompt injection) instead of ignoring them. " + report.disclaimer},
                    "helpUri": OWASP_URI,
                    "defaultConfiguration": {"level": "error"},
                    "properties": {"standards": STANDARDS, "tags": ["security", "llm", "prompt-injection"]},
                }, {
                    "id": COVERAGE_RULE_ID,
                    "name": "MissingBaselineCoverage",
                    "shortDescription": {"text": "No baseline comparison exists for this measured cell"},
                    "fullDescription": {"text": "Missing comparison evidence is a coverage gap, not evidence that prompt injection succeeded."},
                    "defaultConfiguration": {"level": "error"},
                }, {
                    "id": SAMPLE_RULE_ID, "name": "InsufficientSampleCoverage",
                    "shortDescription": {"text": "Measured observations do not meet the owner-defined minimum"},
                    "defaultConfiguration": {"level": "error"},
                }, {
                    "id": UNCERTAINTY_RULE_ID, "name": "UncertaintyThreshold",
                    "shortDescription": {"text": "The Wilson lower bound does not meet the configured threshold"},
                    "fullDescription": {"text": "A binomial sensitivity summary, not guaranteed population coverage or evidence of an observed successful attack."},
                    "defaultConfiguration": {"level": "error"},
                }, {
                    "id": UTILITY_RULE_ID, "name": "TaskUtilityThreshold",
                    "shortDescription": {"text": "Task completion under attack does not meet the owner-defined floor"},
                    "fullDescription": {"text": "A separate point-rate task utility requirement, not evidence of injection success or clean-task performance."},
                    "defaultConfiguration": {"level": "error"},
                }],
            }},
            "results": results,
            "properties": {"gate_passed": report.passed, "mode": report.mode,
                           "requirements_met": report.requirements_met,
                           "enforcement_status": report.enforcement_status,
                           "uncertainty_boundary": report.meta.get("uncertainty_boundary")},
        }],
    }
    return json.dumps(sarif, indent=2, allow_nan=False)


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------

def emit(report: ScanReport, formats: list[str], *, sarif_out: str, json_out: str,
         config_path: str = ".dspy-security-bench.yaml", use_color: bool = True) -> None:
    """Render each requested format — terminal to stdout, others to their files."""
    for fmt in formats:
        if fmt == "terminal":
            print(render_terminal(report, use_color=use_color))
        elif fmt == "json":
            Path(json_out).write_text(render_json(report))
            print(f"[scan] wrote JSON report → {json_out}")
        elif fmt == "sarif":
            Path(sarif_out).write_text(render_sarif(report, config_path=config_path))
            print(f"[scan] wrote SARIF report → {sarif_out}")
