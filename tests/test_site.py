import json
from html.parser import HTMLParser
from pathlib import Path

from scripts.generate_site_data import (
    BENIGN_DIR,
    DEFAULT_OUT,
    RESULTS_DIR,
    _proofrun_results,
    build_payload,
)

SITE = Path(DEFAULT_OUT).parent


class _AssetCollector(HTMLParser):
    def __init__(self):
        super().__init__()
        self.paths = []

    def handle_starttag(self, tag, attrs):
        attributes = dict(attrs)
        if tag in {"img", "script"} and attributes.get("src"):
            self.paths.append(attributes["src"])
        if tag == "link" and attributes.get("href"):
            self.paths.append(attributes["href"])


def test_site_payload_covers_committed_non_smoke_results():
    payload = build_payload()
    expected = sum(
        not json.loads(path.read_text()).get("smoke") for path in RESULTS_DIR.glob("*.json")
    )
    assert payload["modelCount"] == expected
    assert payload["familyCount"] == len({model["family"] for model in payload["models"]})


def test_site_payload_is_ranked_and_preserves_provisional_status():
    payload = build_payload()
    scores = [model["robustness"] for model in payload["models"]]
    assert scores == sorted(scores, reverse=True)
    assert all(
        model["classification"] == "Provisional"
        for model in payload["models"]
        if model["status"] != "confirmed"
    )


def test_site_capability_is_joined_from_no_attack_evidence():
    payload = build_payload()
    by_model = {model["modelId"]: model for model in payload["models"]}
    for path in BENIGN_DIR.glob("*.json"):
        benign = json.loads(path.read_text())
        if benign["model_id"] in by_model:
            assert by_model[benign["model_id"]]["capability"] == benign["combined_U_benign"]


def test_committed_site_data_matches_result_json():
    assert json.loads(Path(DEFAULT_OUT).read_text()) == build_payload()


def test_site_evidence_links_are_deployable_urls():
    for model in build_payload()["models"]:
        assert model["result"].startswith("https://github.com/immu4989/dspy-security-bench/")


def test_site_referenced_assets_exist():
    collector = _AssetCollector()
    collector.feed((SITE / "index.html").read_text())
    local_paths = [path for path in collector.paths if not path.startswith(("http://", "https://"))]
    assert local_paths
    assert all((SITE / path).is_file() for path in local_paths)


def test_site_presents_impact_twin_without_mislabeling_fixture_as_model_result():
    page = (SITE / "index.html").read_text()
    assert 'id="impact"' in page
    assert "Same facts." in page
    assert "dspy-security-bench impact repeat --trials 10" in page
    assert "95% Wilson interval" in page
    assert "content addressed" in page
    assert "Reference fixture, not a model result" in page
    assert "not predicted loss or a compliance certification" in page


def test_site_presents_framework_onboarding_without_surprise_model_spend():
    page = (SITE / "index.html").read_text()
    assert 'id="connect"' in page
    assert "dspy-security-bench integrate" in page
    assert "dspy-security-bench doctor" in page
    for framework in ("OpenAI", "LangChain", "Pydantic AI", "CrewAI", "AutoGen", "MCP"):
        assert framework in page
    assert "without invoking the agent run loop" in page
    assert "cannot unexpectedly spend model credits" in page


def test_site_presents_control_twin_as_harm_utility_and_recovery_evidence():
    page = (SITE / "index.html").read_text()
    assert 'id="control"' in page
    assert "Policy off" in page
    assert "Policy on" in page
    assert "5<span>/5</span>" in page
    assert "0<span>/5</span>" in page
    assert "$3.69M" in page
    assert "Clean mission utility" in page
    assert "recovery gap" in page
    assert "dspy-security-bench impact control-demo" in page
    assert "not a model result" in page

    script = (SITE / "app.js").read_text()
    assert 'document.querySelector("#control-copy")' in script
    assert "dspy-security-bench impact control-demo" in script


def test_site_presents_repeat_control_uncertainty_without_population_overclaim():
    page = (SITE / "index.html").read_text()
    assert "RepeatControlTwin · on main" in page
    assert "One delta can be luck" in page
    assert "25/25 · lower bound 86.7%" in page
    assert "15/25 · 40.7%–76.6%" in page
    assert "exact McNemar p" in page
    assert "fresh agent · every case · every condition" in page
    assert "fixed synthetic suite" in page
    assert "not a model result, population estimate" in page
    assert "dspy-security-bench impact control-repeat-demo --trials 5" in page

    script = (SITE / "app.js").read_text()
    assert 'document.querySelector("#repeat-control-copy")' in script
    assert "dspy-security-bench impact control-repeat-demo --trials 5" in script


def test_site_never_upgrades_a_claimed_attestation_without_registry_verification(
    tmp_path, monkeypatch
):
    submissions = tmp_path / "impact"
    submissions.mkdir()
    digest = "a" * 64
    (submissions / "agent.json").write_text(
        json.dumps(
            {
                "bundle_sha256": digest,
                "submission": {"submitter": "<unsafe>"},
                "report": {
                    "agent": "agent <unsafe>",
                    "summary": {
                        "trials": 10,
                        "unstable_pairs": 0,
                        "attack_resistance": {"rate": 1, "lower": 0.9, "upper": 1},
                        "usage": {},
                    },
                },
                "provenance": {
                    "provider": "github_actions",
                    "builder_kind": "dspy_security_bench_reusable_workflow",
                },
            }
        )
    )
    reproductions = tmp_path / "reproductions.json"
    reproductions.write_text('{"schema_version": 1, "reproductions": {}}')
    attestations = tmp_path / "attestations.json"
    attestations.write_text('{"schema_version": 1, "attestations": {}}')
    monkeypatch.setattr(
        "scripts.generate_site_data._site_eligible",
        lambda _: True,
    )

    rows = _proofrun_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "github_attestation_unverified"

    attestations.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "attestations": {digest: {"evidence_tier": "trusted_builder"}},
            }
        )
    )
    rows = _proofrun_results(submissions, reproductions, attestations)
    assert rows[0]["evidenceTier"] == "trusted_builder"


def test_site_escapes_untrusted_community_fields_before_rendering():
    script = (SITE / "app.js").read_text()
    assert "escapeHtml(result.agent)" in script
    assert "escapeHtml(result.submitter)" in script
    assert "safeResultUrl(result.result)" in script
    assert "const button = event.currentTarget;" in script
    assert "setTimeout(() => { event.currentTarget" not in script
