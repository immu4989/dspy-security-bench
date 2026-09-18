import json
from html.parser import HTMLParser
from pathlib import Path

from dspy_security_bench.supplychain.portfolio import build_portfolio_artifacts
from dspy_security_bench.supplychain.portfolio_html import render_portfolio_html

ROOT = Path(__file__).resolve().parents[1]


def artifacts():
    examples = ROOT / "examples"
    manifest = json.loads((examples / "ai-supplier-portfolio.json").read_text())
    policy = json.loads((examples / "ai-bom-disclosure-policy.json").read_text())
    return build_portfolio_artifacts(manifest, policy, examples)


class Surfaces(HTMLParser):
    def __init__(self):
        super().__init__()
        self.tags = []
        self.links = []
        self.attributes = []

    def handle_starttag(self, tag, attrs):
        self.tags.append(tag)
        self.attributes.extend(attrs)
        if tag == "a":
            self.links.append(dict(attrs)["href"])


def test_html_is_self_contained_accessible_and_links_only_declared_artifacts():
    pack = artifacts()
    html = pack["review.html"].decode()
    surfaces = Surfaces()
    surfaces.feed(html)
    assert "script" not in surfaces.tags
    assert "iframe" not in surfaces.tags
    assert "img" not in surfaces.tags
    assert "Content-Security-Policy" in html
    assert "default-src 'none'" in html
    assert 'lang="en"' in html
    assert "Skip to review" in html
    assert "@media print" in html
    assert "@media(max-width:650px)" in html
    assert surfaces.tags.count("h1") == 1
    assert surfaces.tags.count("caption") == 2
    assert all(not key.startswith("on") for key, _ in surfaces.attributes)
    assert all(link.startswith("#") or link in pack for link in surfaces.links)
    assert "private/model.bin" not in html


def test_preview_is_bounded_and_caller_text_is_escaped():
    pack = artifacts()
    report = json.loads(pack["portfolio.json"])
    label = report["suppliers"][0]["supplier_id"]
    attack = '<script>alert("private")</script>'
    report["claim_boundary"] = attack
    report["suppliers"][0]["supplier_id"] = attack
    finding = {"standard": attack, "component_id": attack, "field": attack, "count": 1}
    html = render_portfolio_html(report, {attack: {"findings": [finding] * 100}})
    assert attack not in html
    assert "&lt;script&gt;" in html
    assert "First 50 of 100 findings" in html
    assert f"suppliers/{label}/" not in html
    assert "href='suppliers/&lt;script" not in html


def test_invalid_submission_has_no_finding_count_or_evidence_links():
    pack = artifacts()
    report = json.loads(pack["portfolio.json"])
    row = report["suppliers"][0]
    label = row["supplier_id"]
    row.update(
        status="input_invalid",
        finding_count=None,
        intake_manifest_sha256=None,
        error_code="source_unreadable_or_invalid_json",
    )
    report["summary"].update(complete=False, input_invalid=1, evaluated=1, owner_review_required=1)
    html = render_portfolio_html(report, {})
    assert "Incomplete intake" in html
    assert "This submission was not evaluated" in html
    assert f"href='suppliers/{label}/" not in html
