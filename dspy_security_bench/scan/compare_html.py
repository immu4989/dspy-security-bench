"""Script-free presentation of a recomputed matched-case comparison."""

from __future__ import annotations

from html import escape
from typing import Any

MAX_PREVIEW_CASES = 50


def _text(value: Any) -> str:
    return escape(str(value), quote=True)


def _metric(axis: str, counts: dict) -> str:
    counts = {key: _text(value) for key, value in counts.items()}
    return f'''<article class="metric"><h2>{axis}</h2>
<p class="rate">{counts['before_successes']} <span>→</span> {counts['after_successes']}<small>successful cases out of {counts['cases']}</small></p>
<dl><div><dt>New failures</dt><dd class="bad">{counts['new_failures']}</dd></div>
<div><dt>New successes</dt><dd>{counts['new_successes']}</dd></div>
<div><dt>Stable successes</dt><dd>{counts['stable_successes']}</dd></div>
<div><dt>Stable failures</dt><dd>{counts['stable_failures']}</dd></div></dl></article>'''


def _transition(before: int, after: int) -> str:
    labels = {(1, 0): ("bad", "New failure"), (0, 1): ("good", "New success"),
              (1, 1): ("", "Stable success"), (0, 0): ("", "Stable failure")}
    style, label = labels[(before, after)]
    return f'<span class="{style}">{label}</span>'


def render_scan_comparison_html(report: dict) -> str:
    """Render a native recomputed report; this function is not a verifier.

    The CLI invokes native verification first. Identifiers are escaped, no raw
    values are inserted in CSS/URLs, and no scripts or external resources load.
    """
    summary = report["summary"]
    review = report["source_review"]
    met = summary["comparison_requirements_met"]
    status = "New-failure allowances met" if met else "New-failure allowances exceeded"
    changed = report["changed_cases"][:MAX_PREVIEW_CASES]
    rows = []
    for case in changed:
        rows.append(f'''<tr><th scope="row">{_text(case['suite'])}<small>{_text(case['user_task_id'])} / {_text(case['injection_task_id'])}</small></th>
<td>{_text(case['defense'])}<small>{_text(case['attack'])}</small></td>
<td>{_transition(case['before_security'], case['after_security'])}</td>
<td>{_transition(case['before_utility'], case['after_utility'])}</td></tr>''')
    table = (f'''<div class="table-wrap" role="region" aria-label="Changed cases table" tabindex="0"><table>
<caption>Changed case preview — {len(changed)} of {_text(summary['changed_cases'])} changed cases. Full case and cell details remain in the comparison JSON.</caption>
<thead><tr><th scope="col">Suite / case</th><th scope="col">Defense / attack</th><th scope="col">Security</th><th scope="col">Task utility</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>''' if changed else
             '<p class="empty">No case outcomes changed. Unchanged failures still matter; inspect the retained scan requirements below.</p>')
    policy_note = ("Source gate policy or baseline changed. Review those changes separately; this comparison gate does not approve them."
                   if review["gate_policy_changed"] or review["baseline_changed"] else
                   "Source gate policies and baseline snapshots are unchanged.")
    policy = report["comparison_policy"]
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Matched scan review · DSPy Security Bench</title>
<style>
:root{{color-scheme:light;--ink:#112b36;--muted:#49616a;--line:#c9d8dc;--paper:#f2f7f6;--teal:#075f58;--red:#a51c2b}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,-apple-system,sans-serif}}
main{{max-width:1120px;margin:auto;padding:56px 28px}}a{{color:var(--teal)}}.eyebrow{{font-size:12px;letter-spacing:.16em;text-transform:uppercase;font-weight:750;color:var(--teal)}}
h1{{font-size:clamp(36px,6vw,60px);line-height:1.08;letter-spacing:-.045em;max-width:800px;margin:18px 0}}h2{{line-height:1.2;font-size:22px}}p{{max-width:850px}}.lede{{font-size:19px;color:var(--muted)}}
.status{{display:inline-block;border:1px solid var(--line);border-radius:8px;background:white;padding:10px 16px;font-weight:700}}.status.failed{{color:var(--red);border-color:#cd9fa6}}
.metrics{{display:grid;grid-template-columns:1fr 1fr;gap:22px;margin:30px 0}}.metric,.panel{{background:white;border:1px solid var(--line);border-radius:14px;padding:26px}}
.metric h2{{margin:0;color:var(--muted)}}.rate{{font-size:44px;font-weight:750;line-height:1.2;margin:22px 0}}.rate span{{color:var(--muted);font-weight:400}}small{{display:block;font-size:13px;line-height:1.5;color:var(--muted);font-weight:400;margin-top:5px}}
dl{{margin:0}}dl div{{display:flex;justify-content:space-between;gap:20px;padding:8px 0;border-top:1px solid var(--line)}}dd{{font-weight:750;margin:0}}.bad{{color:var(--red);font-weight:700}}.good{{color:var(--teal);font-weight:700}}
.panel{{margin:26px 0}}.panel h2{{margin-top:0}}.table-wrap{{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:10px;background:white}}table{{border-collapse:collapse;min-width:620px;width:100%;font-size:14px}}caption{{text-align:left;padding:18px;font-weight:600}}th,td{{padding:14px 18px;text-align:left;border-top:1px solid var(--line);vertical-align:top}}thead{{background:#e8f1ef}}tbody th{{font-weight:600;max-width:350px;overflow-wrap:anywhere}}
:focus-visible{{outline:3px solid #075f58;outline-offset:4px}}code{{display:block;background:#edf3f3;padding:10px;overflow-wrap:anywhere;font-size:12px}}.notice{{border-left:4px solid var(--teal);padding-left:18px;color:var(--muted)}}footer{{font-size:13px;color:var(--muted);margin-top:32px}}.skip{{position:absolute;left:-10000px}}.skip:focus{{left:12px;top:12px;background:white;padding:12px;z-index:1}}
@media(max-width:640px){{main{{padding:34px 18px}}.metrics{{grid-template-columns:1fr;gap:16px}}.metric,.panel{{padding:20px}}.rate{{font-size:38px}}}}
@media print{{body{{background:white}}main{{padding:0;max-width:none}}.metrics{{grid-template-columns:1fr 1fr}}.metric,.panel{{break-inside:avoid}}.table-wrap{{overflow:visible;border:0}}table{{min-width:0;font-size:10px}}th,td{{padding:6px}}.skip{{display:none}}}}
</style></head><body><a class="skip" href="#main">Skip to review</a><main id="main">
<header><div class="eyebrow">DSPy Security Bench · offline review</div><h1>Same cases.<br>See what changed.</h1>
<p class="lede">{_text(summary['paired_cases'])} matched cases. Security and task utility stay separate. Improvements do not erase newly failing cases.</p>
<p class="status {'failed' if not met else ''}">{status}</p></header>
<section class="metrics" aria-label="Security and utility outcomes">{_metric('Security resistance', summary['security'])}{_metric('Task utility', summary['utility'])}</section>
<p class="notice">Meeting a no-new-failures policy is not the same as meeting the original scan requirements. This page is descriptive evidence, not statistical significance, authenticated execution, or approval.</p>
<section class="panel" aria-labelledby="policy"><h2 id="policy">Keep the decision context</h2>
<dl><div><dt>Allowed new security failures</dt><dd>{_text(policy['max_new_security_failures'])}</dd></div>
<div><dt>Allowed new utility failures</dt><dd>{_text(policy['max_new_utility_failures'])}</dd></div>
<div><dt>Before: original scan requirements met</dt><dd>{'Yes' if review['before_requirements_met'] else 'No'}</dd></div>
<div><dt>After: original scan requirements met</dt><dd>{'Yes' if review['after_requirements_met'] else 'No'}</dd></div></dl><p>{policy_note}</p></section>
<section aria-labelledby="cases"><h2 id="cases">Inspect changed cases</h2>{table}</section>
<section class="panel" aria-labelledby="identity"><h2 id="identity">Retain the source evidence</h2>
<p>These canonical digests identify the retained artifacts; they do not authenticate their creator or execution.</p>
<p>Before evidence<code>{_text(report['before_evidence_sha256'])}</code></p>
<p>After evidence<code>{_text(report['after_evidence_sha256'])}</code></p>
<p>Comparison<code>{_text(report['comparison_sha256'])}</code></p></section>
<footer><p>{_text(report['claim_boundary'])}</p><p>No scripts, remote fonts, analytics, or external assets. The preview includes at most {MAX_PREVIEW_CASES} changed cases; retain the full JSON and both source files.</p></footer>
</main></body></html>'''
