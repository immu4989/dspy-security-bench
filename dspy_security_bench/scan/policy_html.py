"""Script-free presentation that separates changed policy from measured outcomes."""
from __future__ import annotations

from html import escape

MAX_FINDING_PREVIEW = 50
PERCENT_FIELDS = {"min_security", "min_utility", "min_joint_success", "max_regression", "warn_margin", "confidence"}
IDENTITY_FIELDS = ("suite", "agent", "defense", "attack", "finding_type")


def _text(value) -> str:
    return escape(str(value), quote=True)


def _state(finding) -> str:
    if finding is None:
        return "No finding emitted"
    return "Met" if finding["passed"] else "Unmet · " + finding["severity"]


def _cutoff(finding) -> str:
    if finding is None:
        return "—"
    if finding.get("required_runs") is not None:
        return f"{finding['required_runs']} observations"
    return "—" if finding["threshold"] is None else f"{finding['threshold']:.2%}"


def _policy_value(policy: dict, key: str) -> str:
    if key not in policy:
        return "Not configured"
    value = policy[key]
    return f"{value:.2%}" if key in PERCENT_FIELDS else str(value).lower() if isinstance(value, bool) else str(value)


def render_policy_review_html(review: dict) -> str:
    """Render a natively verified review. This presentation is not a verifier."""
    summary = review["summary"]
    source = review["source_evidence"]
    before, after = source["policy"], review["proposed_policy"]
    policy_rows = []
    for key in sorted(before.keys() | after.keys()):
        changed = key not in before or key not in after or before[key] != after[key]
        policy_rows.append(f"<tr><th scope='row'><code>{_text(key)}</code></th><td>{_text(_policy_value(before, key))}</td>"
                           f"<td>{_text(_policy_value(after, key))}</td><td>{'Changed' if changed else 'Unchanged'}</td></tr>")
    original = {tuple(f[key] for key in IDENTITY_FIELDS): f for f in source["report"]["findings"]}
    proposed = {tuple(f[key] for key in IDENTITY_FIELDS): f for f in review["reviewed_report"]["findings"]}
    keys = sorted(original.keys() | proposed.keys(), key=lambda key: (
        _state(original.get(key)) == _state(proposed.get(key)), key))
    finding_rows = []
    for key in keys[:MAX_FINDING_PREVIEW]:
        old, new = original.get(key), proposed.get(key)
        identity = " / ".join(key[:4])
        finding_rows.append(f"<tr><th scope='row'>{_text(identity)}<small>{_text(key[4].replace('_', ' '))}</small></th>"
                            f"<td>{_text(_state(old))}<small>Cutoff: {_text(_cutoff(old))}</small></td>"
                            f"<td>{_text(_state(new))}<small>Cutoff: {_text(_cutoff(new))}</small></td></tr>")
    cards = []
    for prefix, title in (("original", "Recorded policy"), ("reviewed", "Proposed policy")):
        met = summary[prefix + "_requirements_met"]
        shortfalls = summary[prefix + "_shortfall_findings"]
        cards.append(f"<article class='card'><h2>{title}</h2><p class='verdict'>{'Requirements met' if met else 'Requirements unmet'}</p>"
                     f"<p>{_text(shortfalls)} shortfall {'finding' if shortfalls == 1 else 'findings'}</p>"
                     f"<p class='muted'>Enforcement: {_text(summary[prefix + '_enforcement_status'].replace('_', ' '))}</p></article>")
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Policy-only review · DSPy Security Bench</title><style>
:root{{color-scheme:light;--ink:#152c36;--muted:#50626a;--line:#cad6d8;--paper:#f4f7f5;--accent:#815014;--teal:#075e59}}
*{{box-sizing:border-box}}body{{margin:0;background:var(--paper);color:var(--ink);font:16px/1.6 system-ui,-apple-system,sans-serif}}main{{max-width:1120px;margin:auto;padding:54px 26px}}a{{color:var(--teal)}}h1{{font-size:clamp(38px,6vw,64px);line-height:1.06;letter-spacing:-.045em;margin:20px 0;max-width:850px}}h2{{font-size:21px;line-height:1.3}}p{{max-width:850px}}.eyebrow{{font-size:12px;font-weight:750;letter-spacing:.15em;text-transform:uppercase;color:var(--accent)}}.lede{{font-size:19px;color:var(--muted)}}.notice{{background:#fff4dd;border:1px solid #dec598;border-left:5px solid var(--accent);padding:18px 22px;border-radius:9px;margin:25px 0}}.notice p{{margin:5px 0}}.cards{{display:grid;grid-template-columns:1fr 1fr;gap:20px;margin:26px 0}}.card,.panel{{background:white;border:1px solid var(--line);border-radius:15px;padding:24px}}.card h2{{margin-top:0;color:var(--muted)}}.verdict{{font-size:28px;font-weight:750;line-height:1.2}}.muted,small{{color:var(--muted)}}small{{display:block;font-size:13px;margin-top:6px}}.panel{{margin:28px 0}}.panel h2{{margin-top:0}}
.table-wrap{{overflow-x:auto;max-width:100%;border:1px solid var(--line);border-radius:10px;background:white}}table{{border-collapse:collapse;width:100%;min-width:650px;font-size:14px}}caption{{padding:15px;text-align:left;font-weight:600}}thead{{background:#e8f0ed}}th,td{{border-top:1px solid var(--line);padding:13px 16px;text-align:left;vertical-align:top}}tbody th{{max-width:340px;overflow-wrap:anywhere}}code{{font-size:12px;overflow-wrap:anywhere}}.digest{{display:block;word-break:break-all;background:#edf3f2;padding:10px}}footer{{font-size:13px;color:var(--muted);margin-top:28px}}.skip{{position:absolute;left:-10000px}}.skip:focus{{left:12px;top:12px;padding:12px;background:white;z-index:1}}:focus-visible{{outline:3px solid var(--teal);outline-offset:4px}}
@media(max-width:700px){{main{{padding:32px 18px}}.cards{{grid-template-columns:1fr}}.card,.panel{{padding:20px}}}}
@media print{{body{{background:white}}main{{padding:0;max-width:none}}.cards{{grid-template-columns:1fr 1fr}}.card,.notice,.panel{{break-inside:avoid}}.table-wrap{{overflow:visible;border:0}}table{{min-width:0;font-size:10px}}th,td{{padding:6px}}.skip{{display:none}}}}
</style></head><body><a class="skip" href="#main">Skip to policy review</a><main id="main">
<header><div class="eyebrow">DSPy Security Bench · post-hoc decision analysis</div><h1>Same evidence.<br>{'Different' if summary['policy_changed'] else 'Unchanged'} requirements.</h1>
<p class="lede">A proposed gate changes how existing observations are judged. It does not change what the agent did.</p></header>
<aside class="notice" aria-label="Not a new benchmark run"><strong>Policy-only review · not a new benchmark run</strong>
<p>{_text(summary['observations_reused'])} observations reused unchanged. <strong>0 new model calls.</strong></p>
<p>{'Policy settings changed.' if summary['policy_changed'] else 'Policy settings are unchanged.'} A passing proposed verdict is not evidence of an improved agent.</p></aside>
<section class="cards" aria-label="Original and proposed verdicts">{''.join(cards)}</section>
<section aria-labelledby="settings"><h2 id="settings">Inspect every policy setting</h2>
<div class="table-wrap" role="region" tabindex="0" aria-label="Policy settings comparison"><table><caption>Recorded settings and owner-proposed settings</caption><thead><tr><th scope="col">Setting</th><th scope="col">Recorded</th><th scope="col">Proposed</th><th scope="col">Change</th></tr></thead><tbody>{''.join(policy_rows)}</tbody></table></div></section>
<section aria-labelledby="findings"><h2 id="findings">How the decision changes</h2><p>Showing {len(finding_rows)} of {len(keys)} cell-requirement rows; {len(keys) - len(finding_rows)} omitted. Changed verdicts first. Full findings remain in JSON.</p>
<p class="muted">“No finding emitted” is not a measured success: the original or proposed report did not emit this finding type. Inspect the policy and full report for its applicability.</p>
<div class="table-wrap" role="region" tabindex="0" aria-label="Policy findings comparison"><table><caption>Same observed cases, different requirements</caption><thead><tr><th scope="col">Cell / requirement</th><th scope="col">Recorded finding</th><th scope="col">Proposed finding</th></tr></thead><tbody>{''.join(finding_rows)}</tbody></table></div></section>
<section class="panel" aria-labelledby="retained"><h2 id="retained">Keep the original evidence</h2><p>The portable JSON retains the original source and proposed policy. Verify it with the native CLI and independently retained pins; this HTML is a presentation, not a verifier.</p>
<p>Original evidence<code class="digest">{_text(review['source_evidence_sha256'])}</code></p><p>Policy review<code class="digest">{_text(review['review_sha256'])}</code></p></section>
<footer><p>{_text(review['claim_boundary'])}</p><p>No scripts, remote assets, analytics, or automatic approval. No post-selection statistical guarantees are introduced.</p></footer>
</main></body></html>'''
