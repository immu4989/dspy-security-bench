"""Portable AssuranceGraph engineering views."""

from __future__ import annotations

import html
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from typing import Any
from uuid import NAMESPACE_URL, uuid5

from dspy_security_bench.assurance.case import CLAIM_BOUNDARY, REPORT_TYPE

OSCAL_VERSION = "1.2.2"


def export_sarif(report: Mapping[str, Any]) -> dict[str, Any]:
    _report_identity(report)
    rules = []
    results = []
    for claim in report["claim_results"]:
        claim_id = claim["claim_id"]
        rules.append(
            {
                "id": claim_id,
                "name": claim_id.replace("-", "_"),
                "shortDescription": {"text": claim["title"]},
                "fullDescription": {"text": claim["statement"]},
                "help": {"text": CLAIM_BOUNDARY},
                "properties": {
                    "category": claim["category"],
                    "criticality": claim["criticality"],
                    "requiredEvidenceKind": claim["required_evidence_kind"],
                },
            }
        )
        if claim["status"] == "supported":
            continue
        level = "error" if claim["status"] in {"violated", "contradicted"} else "warning"
        results.append(
            {
                "ruleId": claim_id,
                "level": level,
                "message": {"text": f"{claim['title']}: {claim['status'].replace('_', ' ')}."},
                "locations": [
                    {"physicalLocation": {"artifactLocation": {"uri": "assurance-case.json"}}}
                ],
                "properties": {
                    "assuranceStatus": claim["status"],
                    "supportingEvidenceIds": claim["supporting_evidence_ids"],
                    "violatingEvidenceIds": claim["violating_evidence_ids"],
                    "staleEvidenceIds": claim["stale_evidence_ids"],
                    "unavailableEvidenceIds": claim["unavailable_evidence_ids"],
                    "mappingStatus": "informative-not-determinative",
                },
            }
        )
    return {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "DSPy Security Bench AssuranceGraph",
                        "informationUri": "https://github.com/immu4989/dspy-security-bench",
                        "rules": rules,
                    }
                },
                "results": results,
                "properties": {
                    "reportSha256": report["report_sha256"],
                    "profileId": report["profile"]["profile_id"],
                    "claimBoundary": CLAIM_BOUNDARY,
                },
            }
        ],
    }


def export_oscal(report: Mapping[str, Any]) -> dict[str, Any]:
    """Export non-determinative OSCAL observations and findings."""

    digest = _report_identity(report)
    namespace = f"https://github.com/immu4989/dspy-security-bench/assurance/{digest}"
    evaluation_time = _iso_time(report["case"]["evaluation_time"])
    observations = []
    findings = []
    for claim in report["claim_results"]:
        claim_id = claim["claim_id"]
        observation_id = str(uuid5(NAMESPACE_URL, namespace + "/observation/" + claim_id))
        observations.append(
            {
                "uuid": observation_id,
                "title": claim["title"],
                "description": claim["statement"],
                "methods": ["TEST"],
                "collected": evaluation_time,
                "props": [
                    {"name": "assurance-claim-id", "value": claim_id},
                    {"name": "local-status", "value": claim["status"]},
                    {
                        "name": "required-evidence-kind",
                        "value": claim["required_evidence_kind"],
                    },
                    {"name": "mapping-status", "value": "informative-not-determinative"},
                ],
                "remarks": CLAIM_BOUNDARY,
            }
        )
        if claim["status"] != "supported":
            findings.append(
                {
                    "uuid": str(uuid5(NAMESPACE_URL, namespace + "/finding/" + claim_id)),
                    "title": f"Assurance claim requires review: {claim['title']}",
                    "description": (
                        f"Local AssuranceGraph status is {claim['status']}. This is an "
                        "engineering finding, not a control determination."
                    ),
                    "target": {
                        "type": "objective-id",
                        "target-id": claim_id,
                        "status": {"state": "not-satisfied"},
                    },
                    "related-observations": [{"observation-uuid": observation_id}],
                }
            )
    return {
        "assessment-results": {
            "uuid": str(uuid5(NAMESPACE_URL, namespace + "/assessment-results")),
            "metadata": {
                "title": f"AssuranceGraph — {report['case']['title']}",
                "last-modified": evaluation_time,
                "version": "1",
                "oscal-version": OSCAL_VERSION,
                "remarks": CLAIM_BOUNDARY,
            },
            "import-ap": {"href": "#owner-supplied-assessment-plan-required"},
            "results": [
                {
                    "uuid": str(uuid5(NAMESPACE_URL, namespace + "/result")),
                    "title": "AssuranceGraph local technical observations",
                    "description": (
                        "Informative observations over verified evidence; an accountable assessor "
                        "must connect these to an owner-approved assessment plan and system boundary."
                    ),
                    "start": evaluation_time,
                    "reviewed-controls": {
                        "control-selections": [
                            {
                                "description": "No normative control selection is asserted.",
                                "include-all": {},
                            }
                        ]
                    },
                    "observations": observations,
                    "findings": findings,
                }
            ],
        }
    }


def render_html(report: Mapping[str, Any]) -> str:
    """Render a standalone, content-safe executive and engineering report."""

    _report_identity(report)
    case, summary = report["case"], report["summary"]
    status = summary["status"]
    claim_cards = "".join(_claim_card(claim) for claim in report["claim_results"])
    evidence_rows = "".join(_evidence_row(item) for item in report["evidence_results"])
    counts = summary["claim_status_counts"]
    status_label = status.replace("_", " ")
    css = """
:root{color-scheme:dark;--ink:#eef8f6;--muted:#8ea7a2;--panel:#0d181b;--line:#21363a;--cyan:#60f5de;--green:#78f0a8;--amber:#ffd166;--red:#ff6b73;--violet:#aa8cff}*{box-sizing:border-box}body{margin:0;background:radial-gradient(circle at 15% 0,#17363b 0,transparent 32%),radial-gradient(circle at 90% 15%,#281d47 0,transparent 28%),#071012;color:var(--ink);font:15px/1.55 Inter,ui-sans-serif,system-ui,sans-serif}.shell{width:min(1180px,calc(100% - 32px));margin:auto;padding:54px 0 72px}.eyebrow{color:var(--cyan);font:700 12px/1 monospace;letter-spacing:.16em;text-transform:uppercase}.hero{display:grid;grid-template-columns:1.3fr .7fr;gap:28px;align-items:end;margin:16px 0 34px}.hero h1{font-size:clamp(38px,6vw,72px);line-height:.95;letter-spacing:-.055em;margin:0}.hero p{color:var(--muted);max-width:690px;font-size:17px}.verdict{border:1px solid var(--line);background:linear-gradient(145deg,#102227dd,#0b1417dd);padding:24px;border-radius:20px;box-shadow:0 24px 80px #0008}.verdict small{display:block;color:var(--muted);letter-spacing:.12em}.verdict strong{display:block;color:var(--amber);font-size:24px;margin:8px 0;text-transform:uppercase}.verdict code{color:var(--cyan)}.metrics{display:grid;grid-template-columns:repeat(5,1fr);gap:10px;margin:28px 0}.metric{border:1px solid var(--line);background:#0b1518;padding:16px;border-radius:14px}.metric b{display:block;font-size:28px}.metric span{color:var(--muted);font-size:11px;text-transform:uppercase;letter-spacing:.08em}.section{margin-top:38px}.section h2{font-size:22px;margin:0 0 16px}.claims{display:grid;grid-template-columns:repeat(2,1fr);gap:14px}.claim{position:relative;overflow:hidden;border:1px solid var(--line);background:linear-gradient(145deg,#101d20,#0a1315);border-radius:16px;padding:20px}.claim:before{content:"";position:absolute;inset:0 auto 0 0;width:4px;background:var(--tone)}.claim header{display:flex;justify-content:space-between;gap:12px}.claim h3{font-size:17px;margin:0}.pill{color:var(--tone);border:1px solid color-mix(in srgb,var(--tone),transparent 45%);background:color-mix(in srgb,var(--tone),transparent 88%);border-radius:999px;padding:4px 9px;font:700 10px monospace;text-transform:uppercase}.claim p{color:var(--muted)}.claim footer{display:flex;gap:8px;flex-wrap:wrap}.tag{font:11px monospace;color:#b9cbc8;background:#132327;border-radius:6px;padding:5px 7px}.supported{--tone:var(--green)}.violated,.contradicted{--tone:var(--red)}.stale_evidence{--tone:var(--amber)}.missing_evidence{--tone:var(--violet)}table{width:100%;border-collapse:collapse;background:#0a1416;border:1px solid var(--line);border-radius:14px;overflow:hidden}th,td{text-align:left;padding:13px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font:700 11px monospace;letter-spacing:.08em;text-transform:uppercase}td code{color:var(--cyan);word-break:break-all}.boundary{margin-top:34px;border:1px solid #3a334d;background:#171324;padding:20px;border-radius:14px;color:#c9bedf}.footer{color:var(--muted);margin-top:30px;font-size:12px}@media(max-width:780px){.hero{grid-template-columns:1fr}.metrics{grid-template-columns:repeat(2,1fr)}.claims{grid-template-columns:1fr}th:nth-child(3),td:nth-child(3){display:none}}
"""
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>{_h(case["title"])} — AssuranceGraph</title><style>{css}</style></head>
<body><main class="shell"><div class="eyebrow">DSPy Security Bench · AssuranceGraph v1</div>
<section class="hero"><div><h1>{_h(case["title"])}</h1><p>{_h(case["description"])}</p></div><aside class="verdict"><small>PROFILE EVIDENCE STATUS</small><strong>{_h(status_label)}</strong><span>{_h(report["profile"]["title"])}</span><br><code>sha256:{_h(report["report_sha256"][:16])}…</code></aside></section>
<section class="metrics"><div class="metric"><b>{summary["claim_count"]}</b><span>claims</span></div><div class="metric"><b>{counts["supported"]}</b><span>supported</span></div><div class="metric"><b>{counts["violated"] + counts["contradicted"]}</b><span>conflicts</span></div><div class="metric"><b>{counts["stale_evidence"]}</b><span>stale</span></div><div class="metric"><b>{counts["missing_evidence"]}</b><span>missing</span></div></section>
<section class="section"><h2>Executable claims</h2><div class="claims">{claim_cards}</div></section>
<section class="section"><h2>Evidence ledger</h2><table><thead><tr><th>Evidence</th><th>Verification</th><th>Owner</th><th>Digest</th></tr></thead><tbody>{evidence_rows}</tbody></table></section>
<aside class="boundary"><strong>Decision boundary</strong><br>{_h(CLAIM_BOUNDARY)}</aside>
<div class="footer">System: {_h(case["system"]["name"])} · Decision owner: {_h(case["decision_owner"])} · Automatic deployment actions: 0 · Automatic risk acceptances: 0</div></main></body></html>"""


def _claim_card(claim: Mapping[str, Any]) -> str:
    tags = "".join(
        f'<span class="tag">{_h(item)}</span>'
        for item in [claim["required_evidence_kind"], claim["criticality"]]
    )
    return f'<article class="claim {_h(claim["status"])}"><header><h3>{_h(claim["title"])}</h3><span class="pill">{_h(claim["status"].replace("_", " "))}</span></header><p>{_h(claim["statement"])}</p><footer>{tags}</footer></article>'


def _evidence_row(item: Mapping[str, Any]) -> str:
    digest = item.get("actual_sha256") or "unavailable"
    return f"<tr><td><strong>{_h(item['evidence_id'])}</strong><br><small>{_h(item['evidence_kind'])}</small></td><td>{_h(item['verification_status'].replace('_', ' '))}<br><small>age {item['age_seconds']}s / max {item['max_age_seconds']}s</small></td><td>{_h(item['owner'])}</td><td><code>{_h(str(digest)[:16])}…</code></td></tr>"


def _report_identity(report: Mapping[str, Any]) -> str:
    if report.get("report_type") != REPORT_TYPE:
        raise ValueError("unsupported AssuranceGraph report")
    digest = report.get("report_sha256")
    if (
        not isinstance(digest, str)
        or len(digest) != 64
        or any(character not in "0123456789abcdef" for character in digest)
    ):
        raise ValueError("AssuranceGraph report_sha256 is invalid")
    return digest


def _iso_time(timestamp: Any) -> str:
    if isinstance(timestamp, bool) or not isinstance(timestamp, int) or timestamp < 0:
        raise ValueError("AssuranceGraph evaluation_time is invalid")
    try:
        return datetime.fromtimestamp(timestamp, timezone.utc).isoformat().replace("+00:00", "Z")
    except (OSError, OverflowError, ValueError) as exc:
        raise ValueError("AssuranceGraph evaluation_time is outside the supported range") from exc


def _h(value: Any) -> str:
    return html.escape(str(value), quote=True)


def write_json(payload: Mapping[str, Any]) -> str:
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"
