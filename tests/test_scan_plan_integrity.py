import pytest

from dspy_security_bench.scan.cli import build_scan_plan, main, render_scan_plan
from dspy_security_bench.scan.config import ScanConfig


def config(**scan):
    return ScanConfig.from_dict(
        {
            "agent": {"model": "fixture"},
            "scan": {
                "suites": ["workspace"],
                "attacks": ["direct"],
                "defenses": ["none"],
                "user_tasks": 2,
                "injection_tasks": 3,
                **scan,
            },
        }
    )


def test_mixed_dos_and_standard_attacks_have_exact_case_and_auxiliary_counts():
    cfg = config(attacks=["direct", "dos"], defenses=["none", "security_prompt"])
    plan = build_scan_plan(cfg)
    assert plan[0]["cases"] == 16  # 2 users * (3 ordinary + 1 DoS) * 2 defenses
    assert plan[0]["auxiliary_injection_task_runs"] == 6
    assert plan[0]["attack_cases"][1]["injection_task_ids"] == ["injection_task_0"]
    assert plan[0]["attack_cases"][1]["cases"] == 4
    text = render_scan_plan(cfg, plan)
    assert "Total benchmark cases: 16" in text
    assert "additional injection-task utility runs: 6" in text
    assert "DoS single-injection convention" in text


@pytest.mark.parametrize(
    "field,values",
    [
        ("attacks", ["unknown-attack"]),
        ("attacks", ["adaptive:unknown"]),
        ("defenses", ["unknown-defense"]),
        ("attacks", ["direct", "direct"]),
        ("suites", ["workspace", "workspace"]),
        ("defenses", ["none", "none"]),
        ("attacks", "direct"),
        ("defenses", [None]),
        ("suites", []),
    ],
)
def test_invalid_matrix_is_rejected_during_planning(field, values):
    with pytest.raises(ValueError):
        build_scan_plan(config(**{field: values}))


def test_adaptive_plan_requires_no_agent_construction(monkeypatch, capsys):
    def forbidden(*args, **kwargs):
        pytest.fail("planning must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--attacks", "adaptive", "--plan"]) == 0
    assert "No model was called" in capsys.readouterr().out


def test_unknown_attack_cli_returns_configuration_error_before_agent(monkeypatch):
    def forbidden(*args, **kwargs):
        pytest.fail("unknown attacks must not construct an agent")

    monkeypatch.setattr("dspy_security_bench.scan.cli._resolve_agent", forbidden)
    assert main(["--agent-model", "fixture", "--attacks", "unknown-attack"]) == 2
