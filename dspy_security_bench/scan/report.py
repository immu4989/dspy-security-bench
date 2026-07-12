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
    lines.append(" " + "-" * 74)
    for f in report.findings:
        if not f.passed:
            tag = c("33", "WARN") if f.severity == "warning" else c("31", "FAIL")
            lines.append(f"  [{tag}] {f.message}")
    verdict = c("32;1", "PASS") if report.passed else c("31;1", "FAIL")
    lines.append("")
    lines.append(f" Verdict: {verdict}  (exit {report.exit_code})")
    lines.append("")
    lines.append(" " + report.disclaimer)
    lines.append("=" * 78)
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# JSON
# ---------------------------------------------------------------------------

def render_json(report: ScanReport) -> str:
    return json.dumps(report.to_dict(), indent=2)


# ---------------------------------------------------------------------------
# SARIF
# ---------------------------------------------------------------------------

def render_sarif(report: ScanReport, config_path: str = ".dspy-security-bench.yaml") -> str:
    results = []
    for f in report.findings:
        if f.passed:
            continue  # only surface failures in the Security tab
        results.append({
            "ruleId": RULE_ID,
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
                }],
            }},
            "results": results,
            "properties": {"gate_passed": report.passed, "mode": report.mode},
        }],
    }
    return json.dumps(sarif, indent=2)


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
