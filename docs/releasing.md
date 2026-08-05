# Releasing to PyPI

The release workflow builds the sdist and wheel once, validates them, and then
publishes the same artifacts with PyPI Trusted Publishing. No long-lived PyPI
token is stored in GitHub.

## One-time repository setup

1. On PyPI, add a Trusted Publisher for project `dspy-security-bench` with
   owner `immu4989`, repository `dspy-security-bench`, workflow
   `release.yml`, and environment `pypi`.
2. In GitHub, create an environment named `pypi`. Optionally require reviewer
   approval for production releases.

## Release checklist

1. Move the release notes out of `Unreleased` in `CHANGELOG.md`.
2. Set `project.version` in `pyproject.toml` and run `uv lock`.
3. Run `pytest` and `ruff check dspy_security_bench/ tests/`.
4. Build locally with `uv build` and inspect the artifacts if package data
   changed.
5. Create and push a matching tag, for example `v0.5.0` for version `0.5.0`.

The workflow rejects a tag that does not exactly match the package version. It
also runs `twine check` before the separately permissioned publish job begins.
