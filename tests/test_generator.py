"""Tests for synthesis.generator — pure helpers + prompt assembly."""
from __future__ import annotations

import types

import pytest

from dspy_security_bench.synthesis.generator import (
    _is_query_only_task,
    _parse_json_array,
    build_synthesis_prompt,
    extract_tool_specs,
    get_query_only_examples,
)


# ---------------------------------------------------------------------------
# _is_query_only_task
# ---------------------------------------------------------------------------

def _fake_task(prompt: str, ground_truth: str = "answer"):
    return types.SimpleNamespace(PROMPT=prompt, GROUND_TRUTH_OUTPUT=ground_truth)


def test_query_task_is_classified_as_query():
    assert _is_query_only_task(_fake_task("What time is the meeting?"))
    assert _is_query_only_task(_fake_task("Who is invited?"))
    assert _is_query_only_task(_fake_task("How many emails do I have?"))
    assert _is_query_only_task(_fake_task("List my files."))


def test_action_task_is_NOT_classified_as_query():
    assert not _is_query_only_task(_fake_task("Send an email to alice."))
    assert not _is_query_only_task(_fake_task("Create a new event."))
    assert not _is_query_only_task(_fake_task("Delete the file."))


def test_empty_ground_truth_rejects_classification():
    assert not _is_query_only_task(_fake_task("What is the answer?", ground_truth=""))
    assert not _is_query_only_task(_fake_task("What is the answer?", ground_truth=None))


# ---------------------------------------------------------------------------
# Suite-level helpers (use the real workspace suite)
# ---------------------------------------------------------------------------

def test_get_query_only_examples_returns_well_formed_dicts(workspace_suite):
    examples = get_query_only_examples(workspace_suite, k=3)
    assert len(examples) == 3
    for ex in examples:
        assert set(ex.keys()) == {"prompt", "ground_truth"}
        assert isinstance(ex["prompt"], str) and ex["prompt"]
        assert isinstance(ex["ground_truth"], str) and ex["ground_truth"]


def test_extract_tool_specs_returns_all_workspace_tools(workspace_suite):
    specs = extract_tool_specs(workspace_suite)
    assert len(specs) == len(workspace_suite.tools)
    for spec in specs:
        assert "name" in spec
        assert "description" in spec
        assert "parameters" in spec
        assert isinstance(spec["parameters"], list)
    names = {s["name"] for s in specs}
    assert "send_email" in names
    assert "search_calendar_events" in names


# ---------------------------------------------------------------------------
# Prompt assembly
# ---------------------------------------------------------------------------

def test_build_synthesis_prompt_includes_all_sections(workspace_suite):
    specs = extract_tool_specs(workspace_suite)
    examples = get_query_only_examples(workspace_suite, k=3)
    prompt = build_synthesis_prompt(
        suite_name="workspace",
        env_summary="### Calendar events\n- foo\n",
        tool_specs=specs,
        examples=examples,
        n_per_batch=5,
    )
    assert "# Available tools" in prompt
    assert "# Environment state" in prompt
    assert "# Real example tasks" in prompt
    assert "# Your task" in prompt
    assert "5 NEW evaluation tasks" in prompt
    # tools are mentioned by name
    assert "send_email" in prompt


# ---------------------------------------------------------------------------
# JSON parsing
# ---------------------------------------------------------------------------

def test_parse_clean_json_array():
    text = '[{"prompt": "P?", "ground_truth": "G"}, {"prompt": "P2?", "ground_truth": "G2"}]'
    out = _parse_json_array(text)
    assert len(out) == 2
    assert out[0] == {"prompt": "P?", "ground_truth": "G"}


def test_parse_json_with_markdown_fences():
    text = '```json\n[{"prompt": "P?", "ground_truth": "G"}]\n```'
    out = _parse_json_array(text)
    assert len(out) == 1
    assert out[0]["prompt"] == "P?"


def test_parse_json_with_leading_commentary():
    text = 'Here are the tasks:\n[{"prompt": "P?", "ground_truth": "G"}]\nLet me know if you want more.'
    out = _parse_json_array(text)
    assert len(out) == 1


def test_parse_returns_empty_on_garbage():
    assert _parse_json_array("not json at all") == []
    assert _parse_json_array("") == []
    assert _parse_json_array("{}") == []  # object, not array


def test_parse_skips_malformed_items():
    text = '[{"prompt": "P?", "ground_truth": "G"}, {"missing_fields": true}]'
    out = _parse_json_array(text)
    # The malformed second item should be dropped
    assert len(out) == 1
    assert out[0]["prompt"] == "P?"
