"""Script-free HTML for fresh ProofRun decisions; not a verifier of saved reports."""

from __future__ import annotations

import re
from html import escape

from dspy_security_bench.proofrun_collection import REASONS as COLLECTION_REASONS
from dspy_security_bench.proofrun_presentation import ADVICE, BOUNDARY, ENTRY_REASONS
from dspy_security_bench.proofrun_review import ALL_FAMILIES
from dspy_security_bench.proofrun_review import REASONS as REVIEW_REASONS

_DECISIONS = ("Selected checks passed", "Requirements unmet", "Invalid or not reviewed")
_CLASSES = ("pass", "unmet", "invalid")
_AXES = {
    "integrity": {"valid": "Valid", "invalid": "Invalid", "not_checked": "Not checked"},
    "eligibility": {"eligible": "Eligible", "ineligible": "Ineligible", "not_checked": "Not checked"},
    "provenance": {"verified": "Verified", "unverified": "Unverified", "not_checked": "Not checked"},
}
_TIERS = {
    "not_established": "Not established", "self_attested": "Self-attested",
    "github_attestation_unverified": "GitHub attestation unverified", "github_attested": "GitHub attested",
    "trusted_builder": "Trusted builder",
}
_STYLE = """
:root{color-scheme:light;--ink:#102237;--muted:#4b5d74;--line:#cbd5e1;--paper:#fff;
--pass:#075b3f;--pass-bg:#e4f8ee;--unmet:#734400;--unmet-bg:#fff4d2;--invalid:#972f3a;--invalid-bg:#fff0f1}
*{box-sizing:border-box}body{margin:0;background:#f3f6fa;color:var(--ink);font:16px/1.6 system-ui,-apple-system,Segoe UI,sans-serif}
a{color:#164f88;text-underline-offset:.18em}a:focus-visible,summary:focus-visible,[tabindex]:focus-visible{outline:3px solid #164f88;outline-offset:4px}
.skip{position:absolute;left:1rem;top:-6rem;background:white;padding:.7rem;z-index:2}.skip:focus{top:1rem}
.shell{max-width:1120px;margin:auto;padding:32px 24px 56px}.hero{background:#101f35;color:white;padding:38px;border-radius:22px;display:grid;grid-template-columns:1fr auto;gap:24px}
.eyebrow{color:#b8d8ff;letter-spacing:.12em;text-transform:uppercase;font-size:.75rem;font-weight:750;margin:0 0 12px}
h1{font-size:clamp(2rem,5vw,3.5rem);line-height:1.08;letter-spacing:-.045em;margin:0 0 18px}h2{font-size:1.4rem;line-height:1.3;margin:0 0 16px}h3{font-size:1rem;margin:20px 0 8px}
.hero p{max-width:68ch}.hero .description{color:#d9e6f6;margin:0}.run-kind{color:#d9e6f6;font-size:.88rem}.hero-status{text-align:right;align-self:start;max-width:260px}.hero-status p{color:#d9e6f6;font-size:.85rem}
.badge{display:inline-block;border-radius:100px;padding:5px 12px;font-size:.82rem;font-weight:750;line-height:1.5}.pass{color:var(--pass);background:var(--pass-bg)}.unmet{color:var(--unmet);background:var(--unmet-bg)}.invalid{color:var(--invalid);background:var(--invalid-bg)}
.boundary{margin:18px 0 24px;padding:18px 22px;border:1px solid var(--line);border-left:5px solid #164f88;border-radius:10px;background:white}.boundary p{margin:0}.boundary .muted{margin-top:8px}
.muted,small{color:var(--muted)}small{display:block;font-size:.8rem;margin-top:4px}.metrics{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:16px;margin:24px 0}
.metric{border:1px solid var(--line);border-radius:14px;background:white;padding:20px}.metric strong{display:block;font-size:2.3rem;line-height:1.2;margin:9px 0}.metric p{margin:0;font-size:.85rem;color:var(--muted)}
.panel{background:white;padding:24px;border:1px solid var(--line);border-radius:16px;margin:20px 0}.table-scroll{overflow:auto}table{width:100%;border-collapse:collapse;font-size:.9rem}caption{text-align:left;color:var(--muted);margin:0 0 16px}th,td{text-align:left;padding:14px 12px;border-bottom:1px solid var(--line);vertical-align:top}thead th{font-size:.75rem;text-transform:uppercase;letter-spacing:.035em;color:var(--muted);white-space:nowrap}tbody tr:last-child>*{border-bottom:0}th:first-child,td:first-child{padding-left:0}
.entry{background:white;border:1px solid var(--line);border-radius:14px;margin:16px 0;padding:20px 24px}.entry summary{cursor:pointer;font-weight:750}.entry summary .badge{margin-left:12px}.entry .message{margin:16px 0 8px}.advice{border-left:3px solid var(--line);padding-left:14px;color:var(--muted)}
.entry-grid{display:grid;grid-template-columns:1fr 1fr;gap:32px}.key-values{display:grid;grid-template-columns:minmax(120px,1fr) 1.5fr;gap:8px 16px;font-size:.88rem;margin:0}.key-values dt{color:var(--muted)}.key-values dd{margin:0;font-weight:600;overflow-wrap:anywhere}
.fingerprints{margin-top:22px;padding-top:14px;border-top:1px solid var(--line)}.fingerprints dl{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:12px 0 0}.fingerprints dt{font-size:.75rem;color:var(--muted);margin-bottom:5px}.fingerprints dd{margin:0}code{font: .78rem/1.6 ui-monospace,SFMono-Regular,Consolas,monospace;overflow-wrap:anywhere;white-space:normal;display:block}
.attention{border-left:5px solid var(--invalid)}footer{font-size:.85rem;color:var(--muted);margin-top:28px}footer p{margin:8px 0}.legend{display:grid;grid-template-columns:repeat(3,1fr);gap:24px}.legend p{margin:0;font-size:.85rem;color:var(--muted)}.legend strong{display:block;color:var(--ink);margin-bottom:6px}
@media(max-width:700px){.shell{padding:16px 14px 36px}.hero{padding:24px;grid-template-columns:1fr}.hero-status{text-align:left;max-width:none}.hero-status p{margin:8px 0 0}.metrics{gap:8px}.metric{padding:12px}.metric .badge{padding:3px 6px;font-size:.72rem}.panel,.entry{padding:18px}.entry-grid,.legend,.fingerprints dl{grid-template-columns:1fr;gap:18px}.key-values{grid-template-columns:1fr 1fr}.entry summary .badge{margin:8px 0 0;display:table}}
@media print{body{background:white;color:#102237}.shell{max-width:none;padding:0}.hero{border:1px solid #102237;background:white;color:#102237;border-radius:0;padding:20px}.hero .eyebrow,.hero .description,.hero .run-kind,.hero-status p{color:#102237}.panel,.entry,.metric,.boundary{box-shadow:none;break-inside:avoid}.skip{display:none}a{color:#102237}thead{display:table-header-group}table{font-size:.8rem}.table-scroll{overflow:visible}.entry-grid{gap:18px}}
"""


def _text(value) -> str:
    return escape("".join(char if ord(char) >= 32 else " " for char in str(value)), quote=True)


def _label(labels, value, default):
    return labels.get(value, default) if isinstance(value, str) else default


def _code(value) -> int:
    return value if type(value) is int and value in (0, 1, 2) else 2


def _hash(value) -> str:
    return value if isinstance(value, str) and re.fullmatch(r"[a-f0-9]{64}", value) else "Not available"


def _badge(code) -> str:
    return f'<span class="badge {_CLASSES[code]}">{_DECISIONS[code]}</span>'


def _family(value) -> str:
    return ALL_FAMILIES[value][3] if isinstance(value, str) and value in ALL_FAMILIES else "Family not established"


def _pairs(rows) -> str:
    return '<dl class="key-values">' + "".join(f"<dt>{_text(key)}</dt><dd>{_text(value)}</dd>" for key, value in rows) + "</dl>"


def _fingerprints(rows) -> str:
    return '<div class="fingerprints"><h3>Exact identities</h3><dl>' + "".join(
        f"<div><dt>{_text(label)}</dt><dd><code>{_hash(value)}</code></dd></div>" for label, value in rows
    ) + "</dl></div>"


def _policy(policy) -> str:
    if not isinstance(policy, dict):
        return '<p class="muted">Policy details not recorded; consult the original review request.</p>'
    minimum = policy.get("minimum_trials")
    trial_label = "Structural (no trial-confidence claim)" if minimum is None else (
        f"At least {minimum} repeated trials" if type(minimum) is int and minimum >= 2 else "Not established")
    return _pairs([
        ("Review kind", trial_label),
        ("Provenance mode", _label({"offline": "Offline: not authenticated", "online": "Online verification requested"}, policy.get("mode"), "Not established")),
        ("Trusted builder", "Required" if policy.get("require_trusted_builder") is True else "Not required"),
        ("Self-hosted runners", "Rejected" if policy.get("deny_self_hosted_runner") is True else "Allowed by selected policy"),
    ])


def _entry(position, native, *, row=None):
    native = native if isinstance(native, dict) else {}
    row = row or {}
    code = _code(native.get("exit_code"))
    reason = native.get("reason_code") if native else row.get("status")
    messages = REVIEW_REASONS if native else ENTRY_REASONS
    message = _label(messages, reason, "Required evidence was not reviewed.")
    advice = _label(ADVICE, reason, "Retain the original evidence and rerun the native review before making a decision.")
    family = _family(native.get("bundle_type") or row.get("expected_bundle_type"))
    axes = [_label(_AXES[field], native.get(field), "Not checked") for field in _AXES]
    overview = f'<tr><th scope="row"><a href="#entry-{position}">Entry {position}</a><small>{_text(family)}</small></th><td>{_badge(code)}</td>'
    overview += "".join(f"<td>{_text(value)}</td>" for value in axes) + "</tr>"
    policy = native.get("policy") if isinstance(native.get("policy"), dict) else {}
    identity_rows = [
        ("Input file SHA-256", native.get("input_file_sha256") or row.get("input_file_sha256")),
        ("Expected file SHA-256", row.get("expected_file_sha256") or policy.get("expected_file_sha256")),
        ("Native bundle SHA-256", native.get("bundle_sha256")),
        ("Expected repository fingerprint", policy.get("expected_repository_sha256")),
    ]
    if row:
        identity_rows.append(("Owner entry ID fingerprint", row.get("entry_id_sha256")))
    detail = f'<details class="entry" id="entry-{position}" open><summary>Entry {position} &middot; {_text(family)} {_badge(code)}</summary>'
    detail += f'<p class="message">{_text(message)}</p><p class="advice">{_text(advice)}</p><div class="entry-grid"><section><h3>Decision dimensions</h3>'
    detail += _pairs(list(zip(("Integrity", "Eligibility", "Provenance"), axes, strict=True)) + [
        ("Evidence tier", _label(_TIERS, native.get("evidence_tier"), "Not established")), ("Exit code", code),
    ])
    detail += '</section><section><h3>Selected policy</h3>' + _policy(native.get("policy")) + "</section></div>"
    detail += _fingerprints(identity_rows) + "</details>"
    return code, overview, detail


def _render(review, entries, *, collection=False):
    code = _code(review.get("exit_code"))
    rows, details = "".join(item[1] for item in entries), "".join(item[2] for item in entries)
    counts = [sum(item[0] == outcome for item in entries) for outcome in range(3)]
    title = "Collection evidence review" if collection else "Evidence review"
    messages = COLLECTION_REASONS if collection else REVIEW_REASONS
    message = _label(messages, review.get("reason_code"), "Review could not be established.")
    kind = f"{len(entries)} required evidence slots" if collection and entries else "Single artifact" if not collection else "Plan not admitted"
    metrics = "".join(f'<article class="metric">{_badge(i)}<strong>{counts[i]}</strong><p>Required evidence slots</p></article>' for i in range(3))
    metrics = '<div class="metrics">' + metrics + '</div>'
    if not entries:
        metrics = '<section class="panel attention"><h2>No evidence reviewed</h2><p>The plan was not admitted. This is an error, not an empty successful review.</p></section>'
    table = f'''<section class="panel"><h2>Required evidence</h2>
<div class="table-scroll" role="region" aria-label="Required evidence outcomes" tabindex="0"><table>
<caption>Every required slot is shown. Missing or unreviewed evidence is never marked as passed or skipped.</caption>
<thead><tr><th scope="col">Required slot</th><th scope="col">Decision</th><th scope="col">Integrity</th><th scope="col">Eligibility</th><th scope="col">Provenance</th></tr></thead><tbody>{rows}</tbody></table></div></section>''' if entries else ""
    plan = ""
    if collection:
        plan = '<section class="panel"><h2>Plan identity</h2><p class="muted">A caller-supplied pin identifies expected bytes; it does not authenticate the owner or prove requirement completeness.</p>'
        plan += _fingerprints([("Observed plan SHA-256", review.get("plan_file_sha256")), ("Caller-supplied plan SHA-256", review.get("expected_plan_file_sha256"))]) + "</section>"
    source = f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>ProofRun &mdash; {title}</title><style>{_STYLE}</style></head><body>
<a class="skip" href="#review-content">Skip to review</a><main id="review-content" class="shell">
<header class="hero"><div><p class="eyebrow">DSPy Security Bench / ProofRun</p><h1>{title}</h1><p class="description">{_text(message)}</p><p class="run-kind">{kind}</p></div>
<div class="hero-status">{_badge(code)}<p>Native exit code {code}<br>Unsigned local presentation</p></div></header>
<aside class="boundary" aria-label="Claim boundary"><p><strong>{_text(BOUNDARY)}</strong></p><p class="muted">Offline success does not authenticate provenance. Valid evidence can include adverse findings; review the native report before an operational decision.</p></aside>
{metrics}{table}
<section class="panel"><h2>Read the three dimensions separately</h2><div class="legend">
<p><strong>Integrity</strong>Whether native evidence passes its own consistency checks. A hash alone is not authenticity.</p>
<p><strong>Eligibility</strong>Whether the evidence meets its family-specific registry rules and selected trial policy, not whether a system is safe.</p>
<p><strong>Provenance</strong>Whether the requested GitHub attestation was verified. Offline review does not check provenance.</p></div></section>
{details}{plan}<footer><p>Verifier version: {_text(str(review.get('verifier_version', 'unknown'))[:160])}. No scripts, remote assets, analytics, or automatic approval.</p>
<p>This HTML is a presentation, not a verifier of saved decisions. Regenerate it from original evidence and retained pins; editing this page cannot create valid evidence.</p>
<p>Labels, paths, and repository names are omitted. Fingerprints remain linkable, not anonymous. All sections start expanded; expand any you collapsed before printing.</p></footer>
</main></body></html>'''
    # Preserve output on non-UTF-8 terminals without losing metadata characters.
    return source.encode("ascii", "xmlcharrefreplace").decode("ascii")


def render_review_html(review: dict) -> str:
    """Present one fresh review without changing its decision or copying source labels."""
    return _render(review, [_entry(1, review)])


def render_collection_html(review: dict) -> str:
    """Present every fresh collection outcome; invalid plans remain visible errors."""
    entries = [_entry(index + 1, row.get("review"), row=row) for index, row in enumerate(review["entries"])]
    return _render(review, entries, collection=True)
