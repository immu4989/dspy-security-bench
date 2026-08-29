# ResilienceGraph

ResilienceGraph answers a resource-allocation question that a vulnerability
list cannot: **which combinations of already verified cyber-defense actions
remain feasible and useful when budget, workforce, disruption tolerance,
supplier concentration, essential-service dependencies, and stressed
availability all matter at once?**

The implementation is an exact, offline decision-support protocol. It accepts
recomputable DefenderTwin reports, excludes fixes that were ineffective,
disruptive, unauthorized, rollback-incomplete, or evidence-incomplete, and
enumerates every subset of the remaining actions. The output is the complete
non-dominated frontier—not a hidden weighted score or vendor ranking.

```text
DefenderTwin reports          owner planning contract
safe / unsafe / incomplete    services · dependencies · units · floors
             │                               │
             └──────────────┬────────────────┘
                            ↓
                recompute source evidence
                            ↓
                 exclude unsafe candidates
                            ↓
             enumerate every eligible subset
                            ↓
     resource · prerequisite · exclusion · concentration
     direct-service · beneficiary-group floors
                            ↓
             replay every declared stress scenario
                            ↓
       exact non-dominated frontier + reviewable CSV
                            ↓
             accountable owner makes the decision
```

It runs no exploit, model, optimizer, solver, collector, or network request and
does not change infrastructure. The five packaged DefenderTwin missions and the
ResilienceGraph campaign are fictional.

## Run it in two commands

```bash
dspy-security-bench portfolio init --out resilience-campaign.json
# Replace the fictional services, mappings, units, groups, constraints, and scenarios.
dspy-security-bench portfolio run resilience-campaign.json \
  --json-out resilience-report.json \
  --csv-out resilience-frontier.csv \
  --require-fully-robust
dspy-security-bench portfolio verify resilience-report.json
```

Or exercise the entire built-in workflow:

```bash
dspy-security-bench portfolio demo --out-dir artifacts/resiliencegraph
```

The demo deliberately includes a hospital remediation that closes its declared
attack paths but breaks mission-safety boundaries. Its valid DefenderTwin
report remains visible, but the candidate is excluded before enumeration.
Unfavorable evidence is preserved rather than silently deleted.

## What is exact

For `n` eligible actions, ResilienceGraph inspects all `2^n` subsets and updates
the non-dominated set as each feasible candidate is evaluated, so it does not
retain every dominated portfolio in memory. The
protocol caps campaigns at 18 actions, so “complete” has a falsifiable meaning
and cannot silently become a heuristic when the problem grows.

A subset is feasible only when all declared hard constraints hold:

- budget, workforce, disruption, and action-count ceilings;
- action prerequisites and pairwise exclusions;
- maximum actions from a single supplier;
- direct coverage of every required service; and
- representation of every required beneficiary group.

Each feasible subset is replayed under every owner-declared scenario. A
scenario only declares unavailable action identifiers; ResilienceGraph does not
infer probabilities. The protocol records:

- active and unavailable selected actions;
- directly addressed services;
- downstream services structurally reachable through declared dependencies;
- represented beneficiary groups;
- missing required services and groups; and
- whether the declared scenario floors remain satisfied.

Direct protection and dependency reach are intentionally separate. Protecting
an upstream software service may reach several downstream services in the
declared graph, but that does **not** prove those services are secure.

## Why there is a frontier, not one score

One portfolio may cover more critical-service weight while another consumes
less workforce or disruption capacity. Collapsing those judgments into a
single score would hide the owner's values.

Portfolio A dominates portfolio B only when A is no worse on every declared
objective and strictly better on at least one:

| Maximize | Minimize |
|---|---|
| Scenarios meeting owner floors | Budget units |
| Worst-case direct critical-service weight | Workforce units |
| Worst-case downstream dependency-reach weight | Disruption units |
| Worst-case beneficiary-group count | Action count |

Every dominated option is removed. All non-dominated options remain available
for review. A deterministic lexicographic `reference_selection` makes tests and
automation stable, but `reference_is_recommendation` is always `false`.

## Evidence boundary

Every action embeds a full DefenderTwin report. Before it is eligible,
ResilienceGraph verifies the report from its mission and proposal, then
requires:

- `effective_and_safe` outcome;
- a passing Trusted Defender Gate; and
- zero content fields processed.

The planning mapping from that candidate to services and beneficiary groups is
still owner supplied. Each eligibility record therefore fixes
`planning_mapping_verified_by_defendertwin` to `false`.

The campaign, protocol, source reports, result, and reference selection are all
content-addressed. Offline verification re-runs the entire enumeration and
requires exact report equality, so changing a scenario, constraint, frontier
metric, exclusion, or decision label is detectable even if an attacker rehashes
only the outer object.

## Campaign contract

### Services

Each service has a stable identifier, sector, community, ordinal criticality
weight from 1 through 5, and zero or more upstream dependencies. Dependencies
must reference declared services and form a directed acyclic graph.

Criticality weights are owner-defined ordinal priorities. They are not dollars,
probabilities, lives, avoided losses, or national criticality determinations.

### Actions

Each action binds:

- a unique identifier and planning name;
- a supplier label used only for concentration constraints;
- directly mapped services and beneficiary groups;
- non-negative budget, workforce, and disruption units;
- prerequisites and symmetric exclusions; and
- one complete DefenderTwin report.

Units are deliberately dimensionless because organizations account for money,
labor, maintenance windows, and operational burden differently. Owners should
document one stable local accounting method and compare only like with like.

### Scenarios

Scenarios are bounded availability counterfactuals such as loss of a shared
provider or maintainer capacity. They are not threat forecasts. At least one is
required, and the example includes a baseline plus two stressed cases.

### Constraints

Constraints express resources, concentration, and minimum representation as
hard floors and ceilings. ResilienceGraph never relaxes an impossible
constraint. It emits `no_feasible_portfolio`, an empty frontier, and no
reference selection.

## Government and public-interest uses

The protocol is designed to be useful without requiring sensitive operational
data:

- **Federal program and system owners** can compare bounded response portfolios
  while retaining the agency's established risk and authorization processes.
- **State, local, tribal, and territorial partners** can represent essential
  public services, limited staff, regional dependencies, and minimum community
  coverage in a reviewable local artifact.
- **Sector Risk Management Agencies and critical-infrastructure partners** can
  author fictional community campaigns that expose cross-sector assumptions
  without publishing facility or vulnerability details.
- **Grant and technical-assistance programs** can compare which declared
  combinations satisfy program floors under resource limits. The output does
  not make an award or eligibility decision.
- **Auditors and oversight teams** can reproduce candidate exclusion, subset
  enumeration, feasibility, scenario results, and the exact frontier from one
  JSON file.

No output identifies nationally critical assets, determines grant priority,
claims NIST/CISA conformance, or supersedes applicable law, policy, records,
privacy, civil-rights, procurement, or authorization requirements.

## Industry and research uses

- **Organizations** can move from an unactionable backlog to explicit tradeoffs
  among safe fixes, shared dependencies, scarce staff, and service continuity.
- **Cybersecurity providers** can submit complete favorable and unfavorable
  DefenderTwin evidence and show how their option behaves inside a transparent
  portfolio contract without claiming a universal ranking.
- **Technology partners** can translate local planning systems to the strict
  JSON schema or consume the flat frontier CSV.
- **Frontier AI laboratories** can compare AI-generated remediation proposals
  only after a deterministic verifier establishes their bounded result.
- **Open-source ecosystems and funders** can represent maintainer capacity and
  downstream reach while keeping dependency reach distinct from verified
  downstream protection.
- **Researchers** can study alternative frontier objectives, uncertainty,
  distributional constraints, and independent reproduction without changing
  the frozen v1 result.

## Standards and policy direction

The crosswalk is informative and non-determinative:

- [NIST CSF 2.0 Profiles](https://www.nist.gov/cyberframework/profiles) connect
  current/target outcomes with mission requirements, risk tolerance, and
  resources. ResilienceGraph starts later, after candidate technical effects
  have evidence.
- [NIST IR 8286 Rev. 1](https://csrc.nist.gov/pubs/ir/8286/r1/final) integrates
  cybersecurity risk with enterprise objectives and risk registers.
- [NIST IR 8286B-upd1](https://doi.org/10.6028/NIST.IR.8286B-upd1) addresses
  prioritizing risk and selecting, recording, and communicating responses.
- [CISA Cross-Sector Cybersecurity Performance Goals](https://www.cisa.gov/cybersecurity-performance-goals)
  emphasize a limited set of high-impact outcomes for resource-constrained
  organizations and aggregate national risk.
- [CISA's Infrastructure Dependency Primer](https://www.cisa.gov/topics/critical-infrastructure-security-and-resilience/resilience-services/infrastructure-dependency-primer/learn)
  explains how interconnected infrastructure can create cascading effects and
  why dependencies matter to community investment.
- [OpenAI's call for collective cyber defense](https://openai.com/collective-cyberdefense/)
  motivates verified fixes, continuous tests, trusted access, traceable agents,
  and reusable public-interest playbooks.

ResilienceGraph is not a CSF Profile, cybersecurity risk register, business
impact analysis, control assessment, or CISA method. It exports its own strict
JSON plus CSV so authorized practitioners can use the evidence inside their
established process.

## Continuous review

ContinuousProof accepts a verified ResilienceGraph report:

```bash
dspy-security-bench watch baseline resilience-report.json \
  --label approved-planning-baseline --out baseline.json
```

It captures campaign identity, eligible and excluded candidates, feasible and
frontier counts, robust-scenario coverage, and reference worst-case direct and
dependency-reach weights. A later comparison requests review when the campaign
or evidence changes. It does not accept the new portfolio or spend resources.

## Honest limitations

- Exact enumeration scales exponentially and is intentionally bounded to 18
  candidates. Larger programs should decompose decisions under accountable
  review rather than relabel a heuristic result as complete.
- Only declared dependencies and availability scenarios exist to the analyzer.
- DefenderTwin's synthetic ground truth is not production validation.
- Resource units, criticality weights, service mappings, groups, and scenarios
  can all be wrong even when the arithmetic is correct.
- Pareto efficiency does not mean acceptable, fair, deployable, or optimal for
  an organization.
- Supplier labels measure declared concentration only; they do not assess
  ownership, subcontractors, software components, or supply-chain risk.
- A digest establishes integrity, not authorship, authenticity, trusted time,
  or independent reproduction.

The project does not claim that portfolio optimization, dependency graphs,
Pareto frontiers, scenario analysis, risk registers, or cyber investment
planning are individually new. The falsifiable contribution is the exact,
privacy-bounded composition of recomputable remediation evidence, unsafe-fix
exclusion, essential-service dependency reach, hard resource and representation
constraints, stressed availability, a complete frontier, and explicit human
decision authority in one offline protocol.
