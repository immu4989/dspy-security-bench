from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
LAB = ROOT / "examples/traceproof-runtime-lab"


def test_reference_lab_pins_runtime_images_and_hardens_containers():
    compose = yaml.safe_load((LAB / "docker-compose.yml").read_text())
    services = compose["services"]
    assert set(services) == {"opa", "collector", "agent"}
    assert services["opa"]["image"] == "openpolicyagent/opa:1.16.2-rootless"
    assert services["collector"]["image"] == "otel/opentelemetry-collector-contrib:0.159.0"
    assert services["agent"]["image"] == "python:3.12.11-slim"
    for service in services.values():
        assert service["read_only"] is True
        assert "no-new-privileges:true" in service["security_opt"]


def test_reference_lab_uses_real_opa_and_otlp_http_without_content_fields():
    agent_source = (LAB / "agent.py").read_text()
    compile(agent_source, str(LAB / "agent.py"), "exec")
    for signal in (
        "dsb.auth.token_audience",
        "dsb.auth.token_passthrough",
        "dsb.mcp.resource_indicator_authorization",
        "dsb.mcp.protected_resource_metadata",
    ):
        assert signal in agent_source
    for forbidden in ("prompt", "completion", "tool.call.arguments", "access_token"):
        assert forbidden not in agent_source

    collector = yaml.safe_load((LAB / "collector.yaml").read_text())
    traces = collector["service"]["pipelines"]["traces"]
    assert traces["receivers"] == ["otlp"]
    assert traces["exporters"] == ["file"]


def test_reference_lab_policy_and_runner_are_bounded_and_recomputable():
    policy = (LAB / "policy.rego").read_text()
    runner = (LAB / "run.sh").read_text()
    assert "import rego.v1" in policy
    assert "default allow := false" in policy
    assert 'input.resource == "https://mcp.example.test/records"' in policy
    assert "docker compose" in runner
    assert 'trace import "$ARTIFACTS/otlp.json"' in runner
    assert 'trace analyze "$ARTIFACTS/trace-evidence.json"' in runner
    assert 'trace mcp analyze "$ARTIFACTS/trace-evidence.json"' in runner
