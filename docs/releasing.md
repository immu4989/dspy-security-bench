# Releasing to PyPI

The release workflow builds the sdist and wheel once, validates them, creates
GitHub/Sigstore provenance attestations, and then publishes the same artifacts
with PyPI Trusted Publishing. No long-lived PyPI token is stored in GitHub.

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
5. If the ProofRun reusable workflow changed, confirm its immutable engine `ref`
   matches the release tag and run the composite-action smoke workflow.
6. Create and push a matching tag, for example `v0.8.0` for version `0.8.0`.
7. Confirm the workflow and PyPI publication succeeded, then create the GitHub
   release from the tag and attach the exact workflow-built artifacts.

The workflow rejects a tag that does not exactly match the package version. It
runs `twine check` and attests the distributions before the separately
permissioned publish job begins. Consumers can verify downloaded artifacts with
`gh attestation verify FILE -R immu4989/dspy-security-bench`; provenance links a
file to the workflow and source commit but is not a claim that the package is
free of vulnerabilities.
