"""Extract a compact markdown summary of an AgentDojo suite's seed environment.

Used to prompt-stuff a synthesis LLM with the env data so it can generate
tasks whose ground-truth answers are grounded in the same env that the
agent will see at test time.

Usage:
    from dspy_security_bench.synthesis.extract_env_data import extract_env_summary
    summary = extract_env_summary("workspace", max_per_collection=15)
    print(summary)
"""
from __future__ import annotations

from typing import Any

from agentdojo.task_suite.load_suites import get_suite

# Per-suite, per-collection extractors. Returns a list of one-line strings.
_FIELD_TRUNCATE = 120


def _truncate(s: Any, n: int = _FIELD_TRUNCATE) -> str:
    s = str(s) if s is not None else ""
    s = s.replace("\n", " ").strip()
    return s if len(s) <= n else s[: n - 3] + "..."


def _workspace_summary(env, max_per_collection: int) -> str:
    parts = ["## Workspace environment\n"]

    # Calendar
    parts.append("### Calendar events")
    events = sorted(env.calendar.events.values(), key=lambda e: e.start_time)
    for ev in events[:max_per_collection]:
        parts.append(
            f"- `event#{ev.id_}` | {ev.start_time.isoformat()} → {ev.end_time.isoformat()} "
            f"| **{ev.title}** at {ev.location or 'n/a'} | "
            f"with: {', '.join(ev.participants) if ev.participants else 'no one'} | "
            f"_{_truncate(ev.description, 80)}_"
        )
    if len(events) > max_per_collection:
        parts.append(f"- ... and {len(events) - max_per_collection} more events")

    # Inbox
    parts.append("\n### Emails")
    emails = sorted(env.inbox.emails.values(), key=lambda e: e.timestamp)
    for em in emails[:max_per_collection]:
        parts.append(
            f"- `email#{em.id_}` | {em.timestamp.isoformat()} | "
            f"from `{em.sender}` to `{', '.join(em.recipients)}` | "
            f"**{em.subject}** | body: _{_truncate(em.body, 100)}_"
        )
    if len(emails) > max_per_collection:
        parts.append(f"- ... and {len(emails) - max_per_collection} more emails")

    # Cloud drive
    parts.append("\n### Files")
    files = sorted(env.cloud_drive.files.values(), key=lambda f: f.last_modified, reverse=True)
    for f in files[:max_per_collection]:
        parts.append(
            f"- `file#{f.id_}` | `{f.filename}` | owner=`{f.owner}` | "
            f"size={f.size} | shared_with=[{', '.join(str(s) for s in (f.shared_with or []))}] | "
            f"content: _{_truncate(f.content, 100)}_"
        )
    if len(files) > max_per_collection:
        parts.append(f"- ... and {len(files) - max_per_collection} more files")

    return "\n".join(parts)


def _generic_summary(env, max_per_collection: int) -> str:
    """Fallback summary that walks pydantic model fields by introspection.

    Used for suites we haven't written a tailored extractor for yet
    (banking, travel, slack).
    """
    parts = [f"## {type(env).__name__}\n"]
    for field_name in type(env).model_fields:
        attr = getattr(env, field_name)
        parts.append(f"### {field_name} ({type(attr).__name__})")
        # find collection-shaped sub-attrs (dicts of pydantic models)
        for sub_name in type(attr).model_fields:
            sub = getattr(attr, sub_name)
            if isinstance(sub, dict) and sub:
                sample = next(iter(sub.values()))
                if hasattr(sample, "model_dump"):
                    items = list(sub.values())[:max_per_collection]
                    parts.append(f"  - {sub_name}: {len(sub)} items, sample fields = "
                                 f"{list(type(sample).model_fields)}")
                    for it in items:
                        compact = {k: _truncate(v, 60) for k, v in it.model_dump().items()}
                        parts.append(f"    - {compact}")
                    if len(sub) > max_per_collection:
                        parts.append(f"    - ... and {len(sub) - max_per_collection} more")
    return "\n".join(parts)


_SUITE_EXTRACTORS = {
    "workspace": _workspace_summary,
}


def extract_env_summary(
    suite_name: str,
    version: str = "v1",
    max_per_collection: int = 15,
) -> str:
    """Produce a markdown summary of an AgentDojo suite's seed environment.

    Args:
        suite_name: One of "workspace", "travel", "banking", "slack".
        version: AgentDojo suite version, default "v1".
        max_per_collection: How many items per collection to include verbatim;
            remaining items are summarized as "... and N more".

    Returns:
        Markdown string suitable for prompt-stuffing.
    """
    suite = get_suite(version, suite_name)
    env = suite.load_and_inject_default_environment({})
    extractor = _SUITE_EXTRACTORS.get(suite_name, _generic_summary)
    return extractor(env, max_per_collection)


if __name__ == "__main__":
    import sys

    suite = sys.argv[1] if len(sys.argv) > 1 else "workspace"
    print(extract_env_summary(suite, max_per_collection=10))
