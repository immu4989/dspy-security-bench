"""Accessible, dependency-free HTML for offline AI supplier reviews."""

from __future__ import annotations

import re
from collections.abc import Mapping
from html import escape
from typing import Any

MAX_PREVIEW_FINDINGS = 50
_LABELS = {
    "requirements_met": "Configured requirements met",
    "owner_review_required": "Disclosure review needed",
    "input_invalid": "Not evaluated",
}
_CSS = """
:root{color-scheme:light;--ink:#142237;--muted:#4b5c73;--line:#d9e3ee;--paper:#f3f6fa;
--blue:#164fc4;--teal:#006a59;--amber:#834a00;--red:#a12b31}
*{box-sizing:border-box}body{margin:0;background:var(--paper);color:var(--ink);
font:16px/1.6 system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}
a{color:var(--blue);text-underline-offset:3px}a:focus-visible,summary:focus-visible{outline:3px solid #dc7400;outline-offset:4px}
.skip{position:absolute;left:1rem;top:-5rem;background:white;padding:.5rem;z-index:2}.skip:focus{top:1rem}
header{background:#10233e;color:#fff;padding:3.5rem max(1.25rem,calc((100% - 1120px)/2)) 5rem;
border-top:6px solid #55d8be}.eyebrow{text-transform:uppercase;letter-spacing:.14em;font-size:.75rem;font-weight:750;color:#95e4d5}
h1{font-size:clamp(2rem,5vw,3.4rem);letter-spacing:-.04em;line-height:1.12;margin:.7rem 0 1rem}
header p{max-width:760px;color:#d3dfed}main{max-width:1160px;margin:-2.3rem auto 0;padding:0 1.25rem 3rem}
.metrics{display:grid;grid-template-columns:repeat(3,1fr);gap:1rem}.metric,.panel,.supplier{background:white;border:1px solid var(--line);border-radius:14px;box-shadow:0 4px 16px #10233e08}
.metric{padding:1.3rem}.metric strong{display:block;font-size:2.1rem;line-height:1.3}.metric span{color:var(--muted);font-size:.9rem}
.metric.invalid{border-top:4px solid var(--red)}.metric.review{border-top:4px solid #d99935}.metric.met{border-top:4px solid var(--teal)}
.panel{padding:1.4rem;margin-top:1.3rem}.panel h2{margin:0 0 .5rem;font-size:1.2rem}.boundary{border-left:4px solid var(--blue)}
.muted{color:var(--muted)}.section-title{margin:2.5rem 0 1rem;font-size:1.5rem}.digest{overflow-wrap:anywhere;font-size:.8rem;font-family:ui-monospace,SFMono-Regular,Consolas,monospace}
.supplier{margin-bottom:1rem;overflow:hidden}.supplier-head{padding:1.3rem 1.4rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
.supplier h3{margin:0;font-size:1.05rem;overflow-wrap:anywhere}.badge{display:inline-block;border-radius:99px;padding:.25rem .7rem;font-size:.78rem;font-weight:700}
.badge.input_invalid{color:#84212a;background:#fde9eb}.badge.owner_review_required{color:#734000;background:#fff0d8}.badge.requirements_met{color:#005343;background:#ddf6ef}
.supplier-body{padding:0 1.4rem 1.3rem}.supplier-body p{margin:.4rem 0}.links{display:flex;gap:1.3rem;flex-wrap:wrap;margin:.8rem 0}
details{border-top:1px solid var(--line);padding-top:.8rem}summary{cursor:pointer;color:var(--blue);font-weight:650;padding:.25rem 0}
.table-wrap{overflow:auto}table{border-collapse:collapse;width:100%;font-size:.86rem;margin:1rem 0}th,td{text-align:left;padding:.6rem;border-bottom:1px solid var(--line);vertical-align:top}th{background:#f3f6fa}td{overflow-wrap:anywhere}caption{text-align:left;color:var(--muted);padding-bottom:.5rem}
code{font-size:.85em;overflow-wrap:anywhere}footer{color:var(--muted);font-size:.83rem;margin-top:2rem}.meta{display:grid;grid-template-columns:1fr 1fr;gap:1.2rem}
@media(max-width:650px){.metrics,.meta{grid-template-columns:1fr}.metric{display:flex;align-items:center;gap:1rem}.metric strong{min-width:2.5rem}header{padding-bottom:4rem}.supplier-head{align-items:flex-start}}
@media print{body{background:white;font-size:10pt}header{background:white;color:#142237;padding:1rem 0;border-top:2px solid #142237}header p,.eyebrow{color:#142237}main{margin:0;padding:0}.metrics{gap:.5rem}.metric,.panel,.supplier{box-shadow:none;break-inside:avoid}.skip{display:none}a{color:#142237}.supplier details{display:none}.links{display:none}h1{font-size:24pt}}
"""


def render_portfolio_html(
    report: Mapping[str, Any], evaluations: Mapping[str, Mapping[str, Any]]
) -> str:
    """Render only review metadata and a bounded finding preview; never execute data."""
    summary = report["summary"]
    completed = (
        "All submissions evaluated"
        if summary["complete"]
        else "Incomplete intake — action required"
    )
    cards = []
    for row in report["suppliers"]:
        supplier_id = row["supplier_id"]
        label = escape(supplier_id)
        status = row["status"]
        # Only a fixed status class and a validated slug become markup attributes.
        css_status = status if status in _LABELS else "input_invalid"
        body = []
        if row["finding_count"] is None:
            body.append(
                "<p>This submission was not evaluated. No zero-finding result or approval can be inferred.</p>"
            )
            body.append(
                f"<p class='muted'>Input category: <code>{escape(row['error_code'] or 'unknown')}</code>. Inspect the retained local submission.</p>"
            )
        else:
            body.append(
                f"<p><strong>{row['finding_count']}</strong> structural findings under the shared policy.</p>"
            )
            # Render links only for the constrained owner label grammar used by the manifest.
            if re.fullmatch(r"[a-z0-9]+(?:-[a-z0-9]+)*", supplier_id):
                body.append(
                    f"<nav class='links' aria-label='Evidence for {label}'><a href='suppliers/{label}/review.md'>Full review</a><a href='suppliers/{label}/policy.report.json'>Evaluation JSON</a><a href='suppliers/{label}/policy.sarif'>SARIF findings</a></nav>"
                )
            findings = evaluations.get(supplier_id, {}).get("findings", [])
            if findings:
                rows = []
                for finding in findings[:MAX_PREVIEW_FINDINGS]:
                    cells = [
                        finding["standard"],
                        finding["component_id"],
                        finding["field"] or finding["finding_type"],
                        str(finding["count"]),
                    ]
                    rows.append(
                        "<tr>" + "".join(f"<td>{escape(cell)}</td>" for cell in cells) + "</tr>"
                    )
                body.append(
                    f"<details><summary>Inspect disclosure findings</summary><div class='table-wrap'><table><caption>First {min(len(findings), MAX_PREVIEW_FINDINGS)} of {len(findings)} findings. The full review retains every finding.</caption><thead><tr><th scope='col'>Standard</th><th scope='col'>Component</th><th scope='col'>Requirement</th><th scope='col'>Count</th></tr></thead><tbody>{''.join(rows)}</tbody></table></div></details>"
                )
        cards.append(
            f"<article class='supplier'><div class='supplier-head'><h3>{label}</h3><span class='badge {css_status}'>{escape(_LABELS.get(status, 'Unknown result'))}</span></div><div class='supplier-body'>{''.join(body)}</div></article>"
        )
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>AI supplier portfolio — offline disclosure review</title><style>{_CSS}</style></head>
<body><a class="skip" href="#main">Skip to review</a><header><div class="eyebrow">DSPy Security Bench · Offline evidence review</div>
<h1>AI supplier portfolio</h1><p>One owner policy. Separate submission outcomes. Reproducible evidence for the next human review.</p></header>
<main id="main"><section class="metrics" aria-label="Submission outcomes">
<div class="metric invalid"><strong>{summary["input_invalid"]}</strong><span>Not evaluated</span></div>
<div class="metric review"><strong>{summary["owner_review_required"]}</strong><span>Disclosure review needed</span></div>
<div class="metric met"><strong>{summary["requirements_met"]}</strong><span>Configured requirements met</span></div></section>
<section class="panel boundary"><h2>{completed}</h2><p>{summary["evaluated"]} of {summary["suppliers"]} submissions evaluated; {summary["finding_count"]} findings across evaluated submissions only.</p>
<p class="muted">{escape(report["claim_boundary"])}</p></section>
<h2 class="section-title">Submission reviews</h2>{"".join(cards)}
<section class="panel"><h2>Reproduction anchors</h2><div class="meta"><div><p class="muted">Shared policy SHA-256</p><p class="digest">{escape(report["policy_sha256"])}</p></div><div><p class="muted">Portfolio report SHA-256</p><p class="digest">{escape(report["report_sha256"])}</p></div></div>
<p><a href="portfolio.json">Portfolio JSON</a> · <a href="review.md">Markdown review</a></p>
<p class="muted">Use <code>dspy-security-bench bom verify-ai-portfolio</code> with the retained manifest, policy, and sources. Verification reproduces the evidence; it does not authenticate the supplier.</p></section>
<footer>No scripts, remote fonts, analytics, or network requests. Labels are owner-assigned. Sharing still requires review of labels, hashes, and disclosure metadata. Print view omits expandable previews; retain the full linked evidence.</footer>
</main></body></html>
"""
