import json
from html.parser import HTMLParser
from pathlib import Path

from scripts.generate_site_data import DEFAULT_OUT, RESULTS_DIR, build_payload

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
    expected = sum(not json.loads(path.read_text()).get("smoke") for path in RESULTS_DIR.glob("*.json"))
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
