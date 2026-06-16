"""Filter synthesized tasks for an AgentDojo suite.

Three independent checks:
  1. Syntactic — the ground_truth string actually appears in the suite's env
     data (catches LLM hallucinations of fake names/emails/dates).
  2. Dedupe — the prompt is not too similar to any real test-suite user task
     (catches synthetic tasks that overlap with the eval set, by sentence-
     embedding cosine).
  3. Solvability (optional, costs API tokens) — gpt-4o-mini given the task
     produces an answer that contains the ground_truth (catches tasks whose
     stated answer is wrong or unreachable).

Usage:
    python -m dspy_security_bench.synthesis.validator workspace \
        synthetic_workspace.jsonl \
        --out synthetic_workspace_validated.jsonl \
        --checks syntactic,dedupe

To add the (paid) solvability check:
    ... --checks syntactic,dedupe,solvability \
        --solvability-model openai/gpt-4o-mini
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Suite-side helpers
# ---------------------------------------------------------------------------

def _collect_workspace_env_strings(env) -> list[str]:
    """Pull all human-readable strings from a workspace env into a flat list."""
    strs: list[str] = []
    for ev in env.calendar.events.values():
        strs += [
            ev.title or "", ev.description or "", ev.location or "",
            ev.start_time.isoformat(), ev.end_time.isoformat(),
            *(ev.participants or []),
            str(getattr(ev, "status", "") or ""),
        ]
    for em in env.inbox.emails.values():
        strs += [
            em.subject or "", em.body or "", em.sender or "",
            em.timestamp.isoformat(),
            *(em.recipients or []),
            *(em.cc or []), *(em.bcc or []),
        ]
    for f in env.cloud_drive.files.values():
        strs += [
            f.filename or "", f.content or "", f.owner or "",
            f.last_modified.isoformat() if hasattr(f.last_modified, "isoformat") else str(f.last_modified),
            *(str(s) for s in (f.shared_with or [])),
        ]
    return [s for s in strs if s]


def _collect_env_strings(env) -> list[str]:
    """Generic fallback: walk model fields and stringify everything."""
    out: list[str] = []
    for field_name in type(env).model_fields:
        attr = getattr(env, field_name)
        for sub_name in type(attr).model_fields:
            sub = getattr(attr, sub_name)
            if isinstance(sub, dict):
                for it in sub.values():
                    if hasattr(it, "model_dump"):
                        for v in it.model_dump().values():
                            if isinstance(v, str):
                                out.append(v)
                            elif isinstance(v, list):
                                out.extend(str(x) for x in v if x)
                            elif v is not None:
                                out.append(str(v))
    return out


_ENV_STRING_COLLECTORS = {
    "workspace": _collect_workspace_env_strings,
}


def get_env_text_corpus(suite_name: str, version: str = "v1") -> str:
    """Return a lowercased concatenation of all env strings, for substring checks."""
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(version, suite_name)
    env = suite.load_and_inject_default_environment({})
    collector = _ENV_STRING_COLLECTORS.get(suite_name, _collect_env_strings)
    return " ⟂ ".join(collector(env)).lower()


def get_real_user_task_prompts(suite_name: str, version: str = "v1") -> list[str]:
    """All real user_task PROMPT strings from the suite — used for dedupe."""
    from agentdojo.task_suite.load_suites import get_suite
    suite = get_suite(version, suite_name)
    return [t.PROMPT for t in suite.user_tasks.values() if t.PROMPT]


# ---------------------------------------------------------------------------
# Validation checks
# ---------------------------------------------------------------------------

@dataclass
class ValidationResult:
    kept: list[dict] = field(default_factory=list)
    dropped: list[dict] = field(default_factory=list)  # task dict + "_reason"
    counts_by_reason: dict[str, int] = field(default_factory=dict)

    def drop(self, task: dict, reason: str) -> None:
        self.dropped.append({**task, "_reason": reason})
        self.counts_by_reason[reason] = self.counts_by_reason.get(reason, 0) + 1

    def keep(self, task: dict) -> None:
        self.kept.append(task)

    def summary(self) -> dict:
        return {
            "kept": len(self.kept),
            "dropped": len(self.dropped),
            "drop_reasons": dict(self.counts_by_reason),
            "kept_pct": round(100 * len(self.kept) / max(1, len(self.kept) + len(self.dropped)), 1),
        }


def check_syntactic(task: dict, env_text_corpus: str) -> str | None:
    """Return None if OK, else a drop-reason string."""
    gt = (task.get("ground_truth") or "").strip().lower()
    if not gt:
        return "syntactic:empty_ground_truth"
    # Number ground truths get special handling — accept either digit or spelled form
    if gt.isdigit():
        return None  # any task with a numeric answer is accepted; we trust the LM
    # Strip surrounding quotes, punctuation that may differ
    gt_normalized = gt.strip("\"'.,;:!? ")
    if not gt_normalized:
        return "syntactic:empty_ground_truth"
    if gt_normalized in env_text_corpus:
        return None
    # Try splitting multi-token ground truths (e.g. "name1@x.com name2@x.com")
    # All space-separated tokens must each appear somewhere in the corpus
    tokens = [t for t in gt_normalized.split() if t]
    if len(tokens) >= 2 and all(t in env_text_corpus for t in tokens):
        return None
    return "syntactic:not_in_env"


def check_dedupe_against_real(
    task: dict,
    real_embeddings,
    encoder,
    threshold: float = 0.9,
) -> str | None:
    """Return None if OK, else drop-reason. Encoder is a sentence-transformers model."""
    prompt = task.get("prompt") or ""
    if not prompt.strip():
        return "dedupe:empty_prompt"
    import numpy as np
    syn_emb = encoder.encode([prompt], normalize_embeddings=True)[0]
    sims = real_embeddings @ syn_emb  # cosine since both normalized
    max_sim = float(np.max(sims))
    if max_sim >= threshold:
        return f"dedupe:overlap_{max_sim:.2f}"
    return None


def check_solvability(
    task: dict,
    suite_name: str,
    env_text_corpus_excerpt: str,
    model: str = "openai/gpt-4o-mini",
) -> str | None:
    """OPTIONAL: ask a small LM if the task is solvable; flag if it can't
    produce an answer containing the ground_truth."""
    import litellm
    prompt = task.get("prompt", "")
    gt = (task.get("ground_truth") or "").strip().lower()
    if not gt:
        return "solvability:empty_ground_truth"
    judge_prompt = (
        f"You are a helpful assistant. The user is working on a {suite_name} "
        f"environment. Here is an excerpt of the data they have access to:\n\n"
        f"{env_text_corpus_excerpt[:8000]}\n\n"
        f"User question: {prompt}\n\n"
        f"Answer concisely, using only the data above. Reply with the answer only."
    )
    try:
        resp = litellm.completion(
            model=model,
            messages=[{"role": "user", "content": judge_prompt}],
            temperature=0.0,
            max_tokens=200,
        )
        ans = resp["choices"][0]["message"]["content"].lower()
    except Exception as e:
        return f"solvability:llm_error:{type(e).__name__}"
    # Same acceptance heuristic as syntactic
    if gt in ans:
        return None
    if gt.isdigit() and gt in ans:
        return None
    tokens = [t for t in gt.split() if t]
    if len(tokens) >= 2 and all(t in ans for t in tokens):
        return None
    return "solvability:wrong_answer"


# ---------------------------------------------------------------------------
# Main entrypoint
# ---------------------------------------------------------------------------

def validate_tasks(
    tasks: list[dict],
    suite_name: str,
    version: str = "v1",
    checks: tuple[str, ...] = ("syntactic", "dedupe"),
    dedupe_threshold: float = 0.9,
    solvability_model: str = "openai/gpt-4o-mini",
) -> ValidationResult:
    result = ValidationResult()

    env_text = get_env_text_corpus(suite_name, version) if "syntactic" in checks or "solvability" in checks else ""

    encoder = None
    real_embeddings = None
    if "dedupe" in checks:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError:
            sys.exit("dedupe check requires sentence-transformers: uv pip install sentence-transformers")
        import numpy as np
        encoder = SentenceTransformer("sentence-transformers/all-MiniLM-L6-v2")
        real_prompts = get_real_user_task_prompts(suite_name, version)
        real_embeddings = encoder.encode(real_prompts, normalize_embeddings=True)

    for task in tasks:
        reason: str | None = None

        if "syntactic" in checks and reason is None:
            reason = check_syntactic(task, env_text)
        if "dedupe" in checks and reason is None:
            reason = check_dedupe_against_real(task, real_embeddings, encoder, dedupe_threshold)
        if "solvability" in checks and reason is None:
            reason = check_solvability(task, suite_name, env_text, solvability_model)

        if reason is None:
            result.keep(task)
        else:
            result.drop(task, reason)

    return result


def _cli():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("suite", choices=["workspace", "banking", "travel", "slack"])
    parser.add_argument("input", type=Path, help="JSONL file of synthetic tasks")
    parser.add_argument("--out", type=Path, help="JSONL file for kept tasks (default: stdout)")
    parser.add_argument(
        "--checks", default="syntactic,dedupe",
        help="comma-separated checks: syntactic, dedupe, solvability",
    )
    parser.add_argument("--dedupe-threshold", type=float, default=0.9)
    parser.add_argument("--solvability-model", default="openai/gpt-4o-mini")
    parser.add_argument(
        "--report", type=Path,
        help="optional: write a JSON validation report (counts, drop reasons)",
    )
    args = parser.parse_args()

    tasks = [json.loads(line) for line in args.input.read_text().splitlines() if line.strip()]
    checks = tuple(c.strip() for c in args.checks.split(",") if c.strip())

    print(f"validating {len(tasks)} tasks for suite={args.suite} checks={checks}", file=sys.stderr)
    result = validate_tasks(
        tasks, suite_name=args.suite, checks=checks,
        dedupe_threshold=args.dedupe_threshold,
        solvability_model=args.solvability_model,
    )

    summary = result.summary()
    print(f"  kept {summary['kept']}/{summary['kept'] + summary['dropped']} "
          f"({summary['kept_pct']}%)", file=sys.stderr)
    print(f"  drop reasons: {summary['drop_reasons']}", file=sys.stderr)

    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps({
            "summary": summary,
            "dropped_sample": result.dropped[:10],
        }, indent=2))
        print(f"  report → {args.report}", file=sys.stderr)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with args.out.open("w") as f:
            for t in result.kept:
                f.write(json.dumps(t) + "\n")
        print(f"  kept tasks → {args.out}", file=sys.stderr)
    else:
        for t in result.kept:
            print(json.dumps(t))


if __name__ == "__main__":
    _cli()
