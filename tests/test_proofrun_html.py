"""Human-readable reports preserve native decisions and the source-redaction boundary."""

import json
import re
from html.parser import HTMLParser
from types import SimpleNamespace

import pytest

from dspy_security_bench import proofrun_cli as cli
from dspy_security_bench import proofrun_collection as collection
from dspy_security_bench import proofrun_html as html
from tests import test_proofrun_collection as collection_fixtures
from tests import test_proofrun_verification_intake as repeated_fixtures
from tests import test_public_submission_metadata as structural_fixtures

healthy = collection_fixtures.healthy
repeated = repeated_fixtures.family
structural = structural_fixtures.family
attested = repeated_fixtures.attested


class Page(HTMLParser):
    def __init__(self, source):
        super().__init__()
        self.tags, self.text = [], []
        self.feed(source)

    def handle_starttag(self, tag, attrs):
        self.tags.append((tag, dict(attrs)))

    def handle_data(self, data):
        self.text.append(data)


def check(source, *, entries, code):
    assert source.startswith("<!doctype html>") and source.isascii()
    assert "PRIVATE" not in source.upper()
    assert f"Native exit code {code}" in source
    assert html.BOUNDARY in source
    assert "not a verifier of saved decisions" in source
    assert "default-src 'none'" in source
    assert "@media print" in source and "@media(max-width:700px)" in source
    page = Page(source)
    assert len([tag for tag, _ in page.tags if tag == "main"]) == 1
    assert not any(tag in {"script", "iframe", "img", "link", "form", "object", "embed", "svg"} for tag, _ in page.tags)
    assert not any(key.startswith("on") for _, attrs in page.tags for key in attrs)
    assert all(attrs["href"].startswith("#") for _, attrs in page.tags if "href" in attrs)
    ids = [attrs["id"] for _, attrs in page.tags if "id" in attrs]
    assert len(ids) == len(set(ids))
    assert all(attrs["href"][1:] in ids for _, attrs in page.tags if "href" in attrs)
    details = [attrs for tag, attrs in page.tags if tag == "details"]
    assert len(details) == entries and all("open" in attrs for attrs in details)
    if entries:
        assert any(tag == "caption" for tag, _ in page.tags)
        assert any(attrs.get("role") == "region" and attrs.get("tabindex") == "0" for _, attrs in page.tags)
    else:
        assert "No evidence reviewed" in source and "not an empty successful review" in source
    return page


@pytest.mark.parametrize("mode", ["pass", "online", "pin", "malformed"])
def test_every_repeated_family_preserves_html_decision(repeated, mode, tmp_path, capsys):
    run_single(repeated, False, mode, tmp_path, capsys)


@pytest.mark.parametrize("mode", ["pass", "online", "pin", "malformed"])
def test_every_structural_family_preserves_html_decision(structural, mode, tmp_path, capsys):
    run_single(structural[1], True, mode, tmp_path, capsys)


def run_single(bundle, structural, mode, tmp_path, capsys):
    path = tmp_path / "PRIVATE.json"
    path.write_text(json.dumps(bundle), encoding="utf-8")
    options = ["--structural"] if structural else ["--minimum-trials", "2"]
    options += [] if mode == "online" else ["--offline"]
    code = 1 if mode == "online" else 0
    if mode == "pin":
        options += ["--expected-file-sha256", "0" * 64]
        code = 2
    elif mode == "malformed":
        path.write_bytes(b'{"PRIVATE":NaN}')
        code = 2
    assert cli.main(["verify", str(path), "--html", *options]) == code
    captured = capsys.readouterr()
    assert captured.err == ""
    check(captured.out, entries=1, code=code)
    if mode == "pass":
        assert "Offline: not authenticated" in captured.out and "Not checked" in captured.out
        assert "Self-attested" in captured.out


@pytest.mark.parametrize("problem", ["none", "missing", "mixed", "pin", "invalid_plan", "budget"])
def test_collection_html_keeps_required_failures_visible(healthy, problem, tmp_path, capsys, monkeypatch):
    path, plan = healthy
    options, code, entries = [], 0, 3
    if problem in {"missing", "mixed"}:
        (tmp_path / plan["entries"][0]["path"]).unlink()
        code = 2
    if problem == "mixed":
        plan["entries"][1]["policy"]["offline"] = False
        path.write_text(json.dumps(plan), encoding="utf-8")
    if problem == "pin":
        options = ["--expected-plan-file-sha256", "0" * 64]
        code, entries = 2, 0
    if problem == "invalid_plan":
        path.write_bytes(b"{}")
        code, entries = 2, 0
    if problem == "budget":
        monkeypatch.setattr(collection, "MAX_TOTAL_BYTES", 1)
        code = 2
    assert cli.main(["verify-collection", str(path), "--html", *options]) == code
    captured = capsys.readouterr()
    assert captured.err == ""
    check(captured.out, entries=entries, code=code)
    counts = [int(n) for n in re.findall(r'<strong>(\d+)</strong>', captured.out)]
    assert sum(counts) == entries
    if problem == "mixed":
        assert counts == [1, 1, 1]
    if problem == "budget":
        assert counts == [0, 0, 3] and "not a skipped requirement" in captured.out


def test_html_counts_are_computed_from_entries_not_summary(healthy):
    path, _ = healthy
    report = collection.review_collection(path)
    report["summary"] = {"required": 999, "passed": 999}
    source = html.render_collection_html(report)
    check(source, entries=3, code=0)
    assert "999" not in source and "3 required evidence slots" in source


def test_only_whitelisted_fields_are_projected_and_html_is_escaped(healthy):
    path, _ = healthy
    report = collection.review_collection(path)
    report["notes"] = report["path"] = "PRIVATE"
    report["verifier_version"] = '<img src="x" onerror="alert(1)">\x00caf\xe9'
    for row in report["entries"]:
        row["id"] = row["path"] = "PRIVATE"
        row["review"]["notes"] = "PRIVATE"
        row["review"]["policy"]["repository"] = "PRIVATE"
    source = html.render_collection_html(report)
    check(source, entries=3, code=0)
    assert "&lt;img" in source and "caf&#233;" in source and "\x00" not in source
    assert html.render_collection_html(report) == source
    assert "url(" not in source and "@import" not in source


def test_missing_fingerprints_and_unknown_labels_do_not_copy_source_text(healthy):
    path, _ = healthy
    report = collection.review_collection(path)
    for row in report["entries"]:
        row["review"].update(bundle_type="PRIVATE", input_file_sha256="PRIVATE", reason_code="PRIVATE",
                             bundle_sha256="PRIVATE", integrity="PRIVATE", eligibility="PRIVATE", provenance="PRIVATE")
        row["input_file_sha256"] = row["expected_file_sha256"] = "PRIVATE"
        row["review"]["policy"]["expected_repository_sha256"] = "PRIVATE"
    source = html.render_collection_html(report)
    check(source, entries=3, code=0)
    assert "Not available" in source


def test_online_verified_is_distinct_from_offline_consistency(attested, monkeypatch, capsys):
    import dspy_security_bench.proofrun as proof
    path, _, _, certificate = attested
    monkeypatch.setattr(proof, "run_bounded", lambda *a, **k: SimpleNamespace(
        returncode=0, stdout=json.dumps([certificate]).encode(), stderr=None,
    ))
    assert cli.main(["verify", str(path), "--html", "--require-trusted-builder"]) == 0
    source = capsys.readouterr().out
    check(source, entries=1, code=0)
    assert "Trusted builder" in source and "Online verification requested" in source
    assert "independent execution reproduction" in source


@pytest.mark.parametrize("command", ["verify", "verify-collection"])
@pytest.mark.parametrize("other", ["--json", "--junit"])
def test_html_is_exclusive_with_other_output_formats(command, other):
    with pytest.raises(SystemExit) as caught:
        cli.main([command, "unused", "--html", other])
    assert caught.value.code == 2


@pytest.mark.parametrize("color,background", [
    ("102237", "ffffff"), ("4b5d74", "ffffff"), ("075b3f", "e4f8ee"),
    ("734400", "fff4d2"), ("972f3a", "fff0f1"), ("b8d8ff", "101f35"), ("d9e6f6", "101f35"),
])
def test_report_text_palette_has_minimum_contrast(color, background):
    assert "#" + color in html._STYLE
    assert "#" + background in html._STYLE or (background == "ffffff" and "background:white" in html._STYLE)
    def luminance(value):
        channels = [int(value[i:i + 2], 16) / 255 for i in (0, 2, 4)]
        linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in channels]
        return sum(v * weight for v, weight in zip(linear, (0.2126, 0.7152, 0.0722), strict=True))
    light, dark = sorted([luminance(color), luminance(background)], reverse=True)
    assert (light + 0.05) / (dark + 0.05) >= 4.5
