# Source evidence registry

This directory is the open, content-addressed ledger for repeated MissionForge and
SourceTwin evidence. Admission establishes that a bundle is structurally valid,
recomputable from raw action traces, uses a fresh agent per case, contains at least
five trials, and has no runtime errors. It does **not** require a favorable score and
does not mean that the system is certified, compliant, unbiased, or safe in production.

## Submit an experiment

1. Run `dspy-security-bench proofrun source --agent package:factory --trials 10
   --submitter @you --agent-source https://… --out my-agent.json`.
2. Verify locally with `dspy-security-bench proofrun verify my-agent.json --offline`.
3. Use a lowercase kebab-case filename, place it in this directory, and open a pull
   request. Do not edit the generated bundle.
4. Describe the agent/version, MissionPack scope, provider, date, and limitations in
   the pull request. Never include secrets, private source material, or production data.

Custom packs are embedded in every report and bound by SHA-256. Their source data must
be synthetic or redistributable, clearly licensed, non-sensitive, and narrow enough for
review. The validator rejects executable hooks; packs are YAML/JSON data only.

See [MissionForge and SourceTwin](../../docs/missionforge.md) for the authoring contract,
metrics, threat model, and interpretation guidance.
