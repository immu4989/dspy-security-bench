"""Tests for synthesis.extract_env_data."""
from __future__ import annotations

import pytest

from dspy_security_bench.synthesis.extract_env_data import extract_env_summary


def test_workspace_summary_contains_collection_headers():
    summary = extract_env_summary("workspace", max_per_collection=5)
    assert "### Calendar events" in summary
    assert "### Emails" in summary
    assert "### Files" in summary


def test_workspace_summary_includes_known_seed_content():
    """The workspace seed env has 'Team Sync' on 2024-05-15."""
    summary = extract_env_summary("workspace", max_per_collection=10)
    assert "Team Sync" in summary
    assert "2024-05-15" in summary


def test_workspace_summary_respects_max_per_collection():
    small = extract_env_summary("workspace", max_per_collection=2)
    big = extract_env_summary("workspace", max_per_collection=15)
    assert len(small) < len(big)


def test_generic_fallback_works_for_banking():
    """Banking suite doesn't have a hand-tuned extractor — verify the generic path runs."""
    summary = extract_env_summary("banking", max_per_collection=5)
    assert isinstance(summary, str)
    assert len(summary) > 100  # should have meaningful content


def test_unknown_suite_raises():
    with pytest.raises(Exception):
        extract_env_summary("bogus_suite_does_not_exist")
