"""Script-free, content-minimal presentation of a recomputed fixed-scope study."""

from __future__ import annotations

from html import escape

from dspy_security_bench.scan.study import AXES

MAX_PREVIEW_CASES = 50
TITLES = {"security": "Security resistance", "utility": "Useful task completion",
          "secure_and_useful": "Secure and useful together"}


def _text(value) -> str:
    return escape(str(value), quote=True)


def _rate(value) -> str:
    return "Not observed" if value is None else f"{value:.1%}"


def render_scan_study_html(report: dict) -> str:
    """Render already-recomputed data; this function is not a source verifier."""
    summary, plan = report["summary"], report["plan"]
    complete, planned = summary["complete_trials"], summary["planned_trials"]
    status = ("Review incomplete" if not summary["all_trials_complete"] else
              "Declared requirements met" if summary["study_requirements_met"] else "Declared requirements unmet")
    cards = []
    for axis in AXES:
        result = summary[axis]
        cards.append(f'''<article class="metric"><h2>{TITLES[axis]}</h2>
<p class="rate">{_text(_rate(result['observed_rate']))}<small>{_text(result['successes'])} successes / {_text(summary['observed_observations'])} observed case-trials</small></p>
<dl><div><dt>Cases with an observed failure</dt><dd>{_text(result['cases_with_observed_failure'])}</dd></div>
<div><dt>Cases with varied outcomes</dt><dd>{_text(result['cases_with_varied_outcomes'])}</dd></div></dl></article>''')
    trials = []
    for trial in report["trials"]:
        state = trial["status"]
        verdict = ("Met" if trial["requirements_met"] else "Unmet") if state == "complete" else "Not measured"
        trials.append(f"<tr><th scope='row'>{_text(trial['trial_id'])}</th><td>{_text(state.replace('_', ' '))}</td>"
                      f"<td>{verdict}</td><td><code>{_text(trial.get('evidence_sha256', 'No complete source'))}</code></td></tr>")
    # The full JSON stays canonical; this review prioritizes variable/failing cases.
    cases = sorted(report["cases"], key=lambda case: (
        not any(case[axis]["varied"] for axis in AXES),
        not any(case[axis]["failures"] for axis in AXES),
        tuple(case[field] for field in ("suite", "agent", "defense", "attack", "user_task_id", "injection_task_id"))))
    case_rows = []
    for case in cases[:MAX_PREVIEW_CASES]:
        identity = " / ".join(case[field] for field in
                              ("suite", "agent", "defense", "attack", "user_task_id", "injection_task_id"))
        values = []
        for axis in AXES:
            item = case[axis]
            label = f"{item['successes']}/{item['observed_trials']}" if item["observed_trials"] else "Not observed"
            values.append(f"<td>{_text(label)}{' <strong>varied</strong>' if item['varied'] else ''}</td>")
        case_rows.append(f"<tr><th scope='row'>{_text(identity)}</th>{''.join(values)}</tr>")
    repeated = "".join(f"<li>{_text(', '.join(group['trial_ids']))}<code>{_text(group['evidence_sha256'])}</code></li>"
                       for group in report["repeated_evidence_groups"])
    repeated = f"<ul>{repeated}</ul>" if repeated else "<p>No repeated digests in these complete sources. Distinct digests still do not establish independent execution.</p>"
    omitted = len(cases) - len(case_rows)
    return f'''<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>Repeated scan review · DSPy Security Bench</title><style>
:root{{color-scheme:light;--ink:#102e35;--muted:#47616a;--line:#c6d7da;--paper:#f2f7f5;--teal:#09645b;--warn:#8a3c19}}
*{{box-sizing:border-box}}body{{margin:0;color:var(--ink);background:var(--paper);font:16px/1.6 system-ui,-apple-system,sans-serif}}main{{max-width:1180px;margin:auto;padding:56px 28px}}a{{color:var(--teal)}}h1{{font-size:clamp(38px,6vw,66px);letter-spacing:-.045em;line-height:1.04;margin:18px 0 24px}}h2{{font-size:21px;line-height:1.25}}p{{max-width:850px}}.eyebrow{{font-size:12px;letter-spacing:.14em;font-weight:750;text-transform:uppercase;color:var(--teal)}}.lede{{font-size:19px;color:var(--muted)}}.status{{display:inline-block;background:white;border:1px solid var(--line);padding:9px 15px;border-radius:8px;font-weight:750;color:var(--warn)}}
.coverage,.panel,.metric{{background:white;border:1px solid var(--line);border-radius:16px;padding:24px}}.coverage{{margin:26px 0}}.coverage p{{margin:8px 0}}progress{{width:100%;height:14px;accent-color:var(--teal)}}.count{{font-size:30px;font-weight:750}}.metrics{{display:grid;grid-template-columns:repeat(3,1fr);gap:18px;margin:24px 0}}.metric h2{{color:var(--muted);margin:0}}.rate{{font-size:36px;line-height:1.2;font-weight:750;margin:24px 0}}small{{display:block;font-size:13px;font-weight:400;line-height:1.5;color:var(--muted);margin-top:8px}}dl{{margin:0}}dl div{{display:flex;justify-content:space-between;gap:12px;border-top:1px solid var(--line);padding:9px 0}}dt{{font-size:14px}}dd{{margin:0;font-weight:750}}.notice{{border-left:4px solid var(--warn);padding-left:18px;color:var(--muted)}}.panel{{margin:26px 0}}.panel h2{{margin-top:0}}
.table-wrap{{max-width:100%;overflow-x:auto;border:1px solid var(--line);border-radius:12px;background:white}}table{{border-collapse:collapse;width:100%;min-width:650px;font-size:14px}}caption{{text-align:left;padding:16px;font-weight:600}}th,td{{text-align:left;vertical-align:top;padding:12px 16px;border-top:1px solid var(--line)}}thead{{background:#e6f0ed}}tbody th{{max-width:350px;overflow-wrap:anywhere}}td strong{{display:block;color:var(--warn);font-size:12px}}code{{display:block;overflow-wrap:anywhere;word-break:break-all;font-size:12px;background:#edf3f2;padding:8px;max-width:100%}}.panel li{{margin-bottom:14px;overflow-wrap:anywhere}}footer{{font-size:13px;color:var(--muted);margin-top:28px}}.skip{{position:absolute;left:-10000px}}.skip:focus{{left:12px;top:12px;background:white;padding:12px;z-index:1}}:focus-visible{{outline:3px solid var(--teal);outline-offset:4px}}
@media(max-width:800px){{.metrics{{grid-template-columns:1fr}}main{{padding:32px 18px}}.metric,.coverage,.panel{{padding:20px}}}}
@media print{{body{{background:white}}main{{padding:0;max-width:none}}.metrics{{grid-template-columns:repeat(3,1fr)}}.metric,.panel,.coverage{{break-inside:avoid}}.table-wrap{{overflow:visible;border:0}}table{{min-width:0;font-size:10px}}th,td{{padding:5px}}code{{font-size:9px}}.skip{{display:none}}}}
</style></head><body><a class="skip" href="#main">Skip to review</a><main id="main">
<header><div class="eyebrow">DSPy Security Bench · fixed-scope study</div><h1>Every attempt<br>counts.</h1>
<p class="lede">Study {_text(plan['study_id'])}. Repeated observations, visible gaps, and separate security and utility outcomes.</p><p class="status">{status}</p></header>
<section class="coverage" aria-labelledby="coverage"><h2 id="coverage">Coverage before conclusions</h2>
<p class="count">{_text(complete)} / {_text(planned)} trials complete</p><progress value="{_text(complete)}" max="{_text(planned)}" aria-label="Complete planned trials">{_text(complete)} of {_text(planned)}</progress>
<p>{_text(summary['missing_trials'])} missing · {_text(summary['execution_error_trials'])} execution errors · {_text(summary['completed_trials_meeting_requirements'])} completed trials met original requirements.</p>
<p>{_text(summary['observed_observations'])} observed of {_text(summary['planned_observations'])} planned case-trials.</p></section>
<p class="notice">Rates below condition on complete trials only. Missing runs and execution errors are not assigned successful or failing binary outcomes. A good conditional rate does not establish a complete or reliable study.</p>
<section class="metrics" aria-label="Observed outcome axes">{''.join(cards)}</section>
<section aria-labelledby="trials"><h2 id="trials">Every planned trial</h2><div class="table-wrap" tabindex="0" role="region" aria-label="Planned trial accounting table"><table><caption>Complete roster, including unmeasured attempts</caption><thead><tr><th scope="col">Trial</th><th scope="col">Status</th><th scope="col">Original requirements</th><th scope="col">Retained evidence digest</th></tr></thead><tbody>{''.join(trials)}</tbody></table></div></section>
<section aria-labelledby="cases"><h2 id="cases">Where outcomes varied</h2><p>Showing {len(case_rows)} of {len(cases)} cases; {omitted} omitted from this preview. Varied outcomes first, then other observed failures. Full JSON retains all cases.</p>
<div class="table-wrap" tabindex="0" role="region" aria-label="Case outcome table"><table><caption>Successes / complete trials for each fixed case</caption><thead><tr><th scope="col">Case identity</th><th scope="col">Security</th><th scope="col">Utility</th><th scope="col">Both together</th></tr></thead><tbody>{''.join(case_rows)}</tbody></table></div></section>
<section class="panel" aria-labelledby="repeated"><h2 id="repeated">Repeated evidence identity</h2><p>Identical digests may mean identical outcomes or reused evidence. They are not proof of separate, independent executions.</p>{repeated}</section>
<section class="panel" aria-labelledby="retain"><h2 id="retain">Keep the review anchors</h2><p>Retain the manifest and every complete source. These digests identify content, not when a plan was made or whether observations are true.</p>
<p>Study plan<code>{_text(plan['plan_sha256'])}</code></p><p>Study report<code>{_text(report['study_sha256'])}</code></p></section>
<footer><p>{_text(report['claim_boundary'])}</p><p>No scripts, remote assets, analytics, or automatic approval. This page is a presentation, not a verifier; use the native CLI and retained sources to recompute it.</p></footer>
</main></body></html>'''
