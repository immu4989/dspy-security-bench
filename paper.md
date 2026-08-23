---
title: 'dspy-security-bench: reproducible mission-assurance evidence for tool-using AI agents'
tags:
  - Python
  - AI agents
  - AI security
  - authorization
  - mission assurance
  - benchmarking
authors:
  - name: Imran Ahamed
    orcid: 0000-0000-0000-0000
    affiliation: 1
affiliations:
  - name: VEZRAN
    index: 1
date: 2026-08-23
bibliography: paper.bib
---

<!--
DRAFT — not submitted.

The repository was made public on 2026-06-16. JOSS's six-month substantial
research-software requirement therefore cannot be met before approximately
2026-12-16. Before submission: replace the placeholder ORCID, confirm the
affiliation, refresh counts and release metadata, and document independent
research use. Feature breadth is not a substitute for external use.
-->

# Summary

Tool-using language-model agents turn model output into external effects. Their
failure surface therefore spans more than indirect prompt injection: an agent
may misuse delegated authority, cross tenant boundaries, follow instructions
embedded in retrieved evidence, omit controlling sources, execute unsafe
incident-response actions, or continue operating after its behavior regresses.
Meaningful evaluation must preserve mission utility, observe functional
effects, bind results to an exact protocol and policy, and keep accountable
decisions outside the scorer.

`dspy-security-bench` is an open Python workbench for producing that evidence.
It combines a reproducible AgentDojo [@debenedetti2024agentdojo] prompt-injection
leaderboard with synthetic counterfactual protocols for procurement, execution
policy, incident response, source grounding, delegated authorization, and
multi-agent authorization paths. It also provides declarative mission packs,
repeated-trial uncertainty, content-addressed evidence, CI gates, provenance,
OSCAL 1.2.2 assessment inputs, continuous evidence comparison, and
vendor-neutral acquisition artifacts.

# Statement of need

Agent evaluations are commonly difficult to compare because they use different
tasks, attacks, safeguards, agent frameworks, sampling units, and definitions
of success. A high refusal rate may hide an agent that fails every legitimate
mission. A strong base-model result may disappear behind a broad tool
credential. A policy demonstration may report blocked calls without measuring
safe recovery. A governance crosswalk may imply assurance without retaining the
underlying observations.

The software addresses this reproducibility gap at three layers. First, it
freezes each protocol and records a canonical SHA-256 identity. Second, it
derives security and utility claims from structured observations and synthetic
state transitions rather than model self-report or an LLM judge. Third, it
preserves raw trial evidence, recomputes published summaries offline, and
separates content integrity, builder provenance, and independent reproduction.

The primary users are researchers studying agent security; engineering teams
placing regression gates around tool-using agents; mission owners authoring
bounded evaluations; identity and policy teams testing delegated authority;
and public or private acquisition teams that need comparable technical inputs
without an automated source-selection decision.

# Design

## Frozen counterfactual protocols

Most specialties use clean/adversarial twins. Structured facts, requested
mission, tool surface, and expected result remain fixed while one untrusted or
security-relevant surface changes. ProcureBench mutates vendor narrative;
IncidentTwin mutates hostile alert context; SourceTwin mutates retrieved
content; AuthorityTwin mutates identity, scope, tenant, audience, revocation,
approval, delegation, intent, sensitivity, or audit state; AgentGraphTwin maps
six of those controls onto multi-hop human-to-agent-to-tool paths.

The protocol, expected outcomes, and policy are serialized and hashed. Reports
cannot silently compare trials run under different contracts. Offline verifiers
reconstruct case, pair, metric, receipt, and digest claims.

## Functional evidence and mission utility

The benchmark records synthetic tool-state transitions and environment-owned
action traces. It reports clean mission utility separately from attack
resistance and harm containment. ControlTwin additionally compares policy-off
and policy-on conditions, separating blocked harm, safe mission recovery, and
clean-utility preservation. SourceTwin scores structured claim and source IDs,
including abstention and material exceptions, without treating an LLM as the
truth oracle.

## Uncertainty and provenance

Repeated protocols instantiate fresh agents or adapters, preserve each trial,
report outcome stability, and use Wilson intervals for fixed-protocol success.
The original model leaderboard uses a cluster bootstrap over task pairs because
temperature-zero repeats are technical replicates. GitHub/Sigstore workflows
can attest exact result bytes and source context. Provenance identifies how
evidence was produced; it does not reveal hosted-model internals or make a
result representative of deployment.

## Mission Assurance Commons

MissionForge defines strict data-only YAML/JSON evaluation packs. InventoryForge
normalizes bounded local public AI inventories, removes contact fields, and
drafts synthetic packs that require owner review. AuthorityBridge translates
OPA, Cedar, OpenFGA, OAuth/MCP, and SPIFFE-shaped decisions into the benchmark
contract without owning backend credentials. ContinuousProof compares verified
evidence identities and metrics using owner-defined thresholds. AcquisitionProof
exports comparable objectives, test plans, portability checks, cost fields, and
reevaluation triggers. FederalProof exports verified repeated evidence as
informative OSCAL 1.2.2 assessment inputs.

# Research positioning

The software complements rather than replaces large red-team studies,
standards, and production monitoring. AgentDojo supplies dynamic task
environments and functional attack-success checks. DSPy [@khattab2024dspy]
supplies the default programmable agent scaffold. NIST's AI Agent Standards
Initiative and agent identity and authorization work motivate interoperable
evaluation around identity, least privilege, delegation, intent, and audit
evidence. U.S. federal AI and acquisition guidance motivates ongoing mission
testing, public use-case inventories, portability, cost observation, and
reviewable evidence. The repository maps to these sources informatively and
does not claim control satisfaction or government endorsement.

# Limitations

Every included protocol is synthetic and covers declared failure classes rather
than all attacks or real missions. Fixed attacks are not adaptively optimized
against each target. Framework adapters, tool descriptions, decoding, provider
updates, latency, identity infrastructure, and production data can change
behavior. Hosted inference is not independently observable from a client-side
trace. Hashes provide tamper evidence rather than signer identity. Repeated
fixed scenarios are not a population sample. Generated inventory packs contain
assumptions, not agency requirements. Acquisition and OSCAL artifacts are
technical inputs, not compliance, source selection, risk acceptance,
certification, or an authorization to operate.

# Acknowledgements

This work builds on AgentDojo [@debenedetti2024agentdojo] for its dynamic agent
security environments and DSPy [@khattab2024dspy] for the default agent
implementation. The project also benefits from public standards and guidance
published by NIST, NCCoE, OMB, GSA, GAO, OWASP, MITRE, and the research
community.

# References
