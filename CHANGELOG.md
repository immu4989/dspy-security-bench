# Changelog

Notable changes to this project. Versions follow the tagged GitHub releases.

The format is loosely based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Entries that **corrected an earlier result** are called out explicitly, because
several of them changed published numbers.

## [Unreleased]

### Added
- **BoundaryDiff evidence for ImpactTwin schema v2.** Every clean/poisoned pair
  now records instrumented environment-owned tool events, identifies the first
  trace divergence and poisoned-only events, and recommends the exact packaged
  procurement policy rule that contains the observed functional harm. The new
  offline `impact explain REPORT.json` command debugs saved reports without a
  model call; SARIF findings carry the same remediation evidence.
- **ImpactTwin / ProcureBench**, a public-interest procurement mission-assurance
  specialty built from five clean/poisoned counterfactual twin pairs. It scores
  utility, causal decision drift, source-selection disclosure, vendor identity
  and eligibility mutation, award-approval bypass, synthetic funds at risk, and
  avoidable price premium from live environment state.
- Offline `impact describe`, `impact manifest`, and `impact demo` commands plus
  `impact run` for any supported agent or LiteLLM model, with a CI resistance
  floor, versioned JSON evidence, frozen-protocol SHA-256 identity, and
  FAR-mapped SARIF findings.
- A procurement policy profile and a public-interest implementation guide with
  methodology, novelty audit, regulatory context, limitations, and extension
  criteria.
- A deterministic policy-as-code execution boundary for any supported agent,
  with allow, deny, and fail-closed human-approval decisions before live tools
  are invoked.
- Offline `policy init`, `policy validate`, `policy check`, and `policy profiles`
  commands, structured audit records, and safe-by-default argument logging.
- Production policy profiles and use-case guides for customer support, accounts
  payable, research/RAG memory protection, and SRE/DevOps copilots.
- A fully responsive interactive leaderboard and product site with model
  filtering, search, evidence links, capability–robustness scatter plot, and a
  CI-scanner quickstart.
- A generated website data layer sourced directly from committed leaderboard
  result JSON, plus a drift check and GitHub Pages deployment workflow.
- A new visual identity and cinematic hero artwork designed around the
  benchmark's trust-boundary concept.

### Fixed
- `spotlight_datamark` now replaces every Unicode whitespace run, closing the
  newline/tab channel that previously left common multiline injections entirely
  unmarked. The adaptive attack registry retains a whitespace-separator probe as
  regression coverage, and the LM-attacker mechanism description now matches
  the implementation.
- Python 3.10 and 3.11 CI compatibility for packaged-resource checks; multi-part
  `Traversable.joinpath` calls are now chained instead of relying on newer
  interpreter behavior.
- GitHub Actions now use current Node 24 releases pinned to immutable commit
  SHAs, and the test workflow pins uv 0.12.3 instead of downloading a drifting
  `latest` tool through the outdated `setup-uv@v3` action.
- The CI matrix now covers every declared Python version from 3.10 through
  3.14. The ordinary `dev` extra no longer installs the optional
  `sentence-transformers`/PyTorch stack, avoiding multi-gigabyte CUDA downloads
  in jobs that never exercise embedding-based synthesis.

## [0.5.0] — 2026-08-05

### Added
- `dspy-security-bench init` generates a ready-to-run config and GitHub Actions
  SARIF workflow while preserving existing files by default.
- `scan --plan` resolves and prints the exact benchmark matrix without building
  an agent or making LM calls.
- Trusted Publishing release workflow with tag/package version verification,
  distribution validation, and a separately permissioned PyPI publish job.

### Fixed
- `scan.injection_tasks` was accepted in YAML but ignored; scans always used
  `injection_task_0`, which is not even present in every AgentDojo suite. Both
  user and injection task counts now resolve to valid, deterministic per-suite
  IDs and reject impossible counts before any LM call.
- Scan configuration now rejects empty matrices, invalid sample sizes, and
  gate thresholds outside `[0, 1]` before starting a paid run.

### Changed
- Package metadata now reflects the shipped v0.5 feature set instead of the
  stale v0.1 metadata still visible on PyPI.
- `sentence-transformers` moved to the optional `synthesis` extra, keeping the
  default scanner installation lighter.

### Corrected
- **`security_prompt` does not survive an adaptive attacker.** v0.3.1 reported
  that the cheap defenses held against an LM-driven iterative attacker. That was
  measured at K=5 rounds. Re-run at K=50 over 10 independent runs, the defense is
  defeated in 9 of them (median 13 rounds; fastest 5). The v0.3.1 budget sat at
  the extreme tail of the rounds-to-break distribution. The README section and
  the adaptive-attack chart are annotated accordingly; raw runs are in
  `data/results/adaptive_budget/`. Total cost of the corrected experiment: ~$0.30.
  The attacker is stochastic, so a single run at any budget is not a measurement.

### Added
- **dspy version pinned as measurement provenance.** dspy 3.3.0 (released
  2026-08-03) changed the tool JSON schema the model receives — defaulted args
  left the `required` list (stanfordnlp/dspy#9971) and tool-call args gained
  `additionalProperties: true` (#10012). The tool schema is part of the
  stimulus, so `protocol.yaml` now records `dspy==3.3.0b1` as the measured
  environment, the runner refuses a mismatched dspy without
  `--allow-dspy-mismatch`, and every new row records the version that produced
  it. Whether the schema change moves any score has not been measured; until it
  is, rows from different dspy versions do not share a board.
- **Model leaderboard** (`LEADERBOARD.md`, `leaderboard/`): a frozen measurement
  protocol, a per-model result JSON for every row, and a generator so the board
  can never drift from its data. 14 models across 10 families.
- **Capability axis.** The runner now records AgentDojo's utility result
  alongside security, and `scripts/run_benign_utility.py` measures task success
  with no injection present. A security number on its own cannot distinguish a
  robust model from one that fails at everything.
- **Subset-validity check.** Four models spanning the range re-measured over
  every task in both suites; all four land inside the subset confidence interval
  with matching buckets.
- `RELATED_WORK.md` — a sourced map of agentic prompt-injection work as of July
  2026, including which widely-cited "leaderboards" rank detectors or human
  red-teamers rather than models.
- `docs/METHODOLOGY.md` — the measurement decisions and an explicit limitations
  section.
- Run checkpointing, per-cell retry, and per-model provider pinning, so a long
  run survives an interruption or a slow upstream provider.

### Fixed
- **Corrected inflated confidence intervals.** Per-suite CIs were bootstrapped
  over pooled repeats, treating `k` technical replicates as independent samples;
  measured, 54 of 56 cells returned byte-identical repeats. Intervals were
  roughly √k too narrow. Now a cluster bootstrap over task pairs. **Five of
  fourteen rows lost their "confirmed" status as a result**, including one
  previously published as a confirmed Robust model on an interval that in fact
  crossed the bucket boundary.
- Checkpoint save ignored its namespace tag, so full-coverage cells could be
  written to the subset checkpoint path and silently reused for a subset row.
  Checkpoints now record their coverage mode and refuse to load across modes.

### Changed
- README repositioned. The capability–robustness decoupling shown by this board
  is an **established result** (Gray Swan ART, the multi-lab IPI competition,
  Google DeepMind), not a finding here; these measurements are consistent with
  that work. The board measures static, fixed-template attacks at k=1 on one
  agent surface and should be read as a lower bound on attackability.

## [0.3.1] — 2026-07-13
### Added
- Adaptive attacks: rule-based (delimiter escape, marker claim, authority
  escalation, task hijack) and an iterative LM-driven attacker.
### Notes
- On Mistral Large / workspace the cheap defenses held at every attacker tier.
  Sample sizes here are small (n=3–5 per cell); treat as a pilot.
- **Superseded.** That conclusion held only at the K=5 attacker budget this
  release tested. At K=50 the `security_prompt` defense is defeated in 9 of 10
  runs. See the Corrected entry under Unreleased.

## [0.3.0] — 2026-07-12
### Added
- Generic agent adapter — benchmark **any** agent, not only DSPy programs.
- `scan` CI gate with SARIF output and OWASP LLM01 / NIST AI 100-2 / MITRE ATLAS
  mappings, so a regression can fail a build.

## [0.2.0] — 2026-07-09
### Added
- Defenses module: security prompt, spotlighting (delimiting and datamarking),
  and sandwich, measurable against every attack.

## [0.1.4] — 2026-07-08
### Added
- Mistral Large probe. Within one family the more capable model was
  substantially more exploitable, indicating robustness and capability are
  separable axes.

## [0.1.3] — 2026-07-01
### Added
- Three-model cross-family probe; three distinct regimes emerge.

## [0.1.2] — 2026-07-01
### Corrected
- Cross-model probe showed the v0.1 optimizer result was **specific to
  gpt-4o-mini** rather than general.

## [0.1.1] — 2026-06-26
### Corrected
- A three-seed sanity check showed the apparent ordering between optimizers in
  v0.1.0 was noise at N=5. The ordering claim was withdrawn.

## [0.1.0] — 2026-06-23
### Added
- First end-to-end run: DSPy optimizers × AgentDojo attacks in one harness,
  workspace suite, single model.

[Unreleased]: https://github.com/immu4989/dspy-security-bench/compare/v0.5.0...HEAD
[0.5.0]: https://github.com/immu4989/dspy-security-bench/compare/v0.3.1...v0.5.0
[0.3.1]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.3.1
[0.3.0]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.3.0
[0.2.0]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.2.0
[0.1.4]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.1.4
[0.1.3]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.1.3
[0.1.2]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.1.2
[0.1.1]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.1.1
[0.1.0]: https://github.com/immu4989/dspy-security-bench/releases/tag/v0.1.0
