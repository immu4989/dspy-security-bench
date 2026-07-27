---
title: 'dspy-security-bench: a reproducible harness for measuring prompt-injection robustness in tool-using LLM agents'
tags:
  - Python
  - machine learning
  - AI security
  - prompt injection
  - LLM agents
  - benchmarking
authors:
  - name: Imran Ahamed
    orcid: 0000-0000-0000-0000
    affiliation: 1
affiliations:
  - name: VEZRAN
    index: 1
date: 2026-07-27
bibliography: paper.bib
---

<!--
DRAFT — not submitted.

JOSS requires a repository to have been public for more than six months with
active development spanning that period. This repository was created
2026-06-16, so the earliest eligible submission is around 2026-12-16. JOSS also
requires evidence that the software is used for research beyond aspirational
statements, which is the thing to build in the interim.

Before submitting: replace the placeholder ORCID, confirm the affiliation, and
refresh the model/family counts and the paragraph describing the leaderboard,
which will have moved on.
-->

# Summary

Language-model agents that call tools put untrusted text into their own context
by design: retrieved documents, tool output, emails, web pages. An indirect
prompt injection hides instructions in that text and attempts to redirect the
agent toward an attacker's goal. Whether a given model resists this is not
predicted by its capability scores, and measuring it requires running a full
agent loop against an environment that can verify whether the attacker actually
succeeded.

`dspy-security-bench` is a Python harness for making that measurement
reproducibly. It wraps the AgentDojo benchmark environments [@debenedetti2024agentdojo]
and adds three things a bare benchmark run does not provide: a frozen
measurement protocol so results from different runs and different people are
comparable, a durability criterion that decides when a result is stable enough
to state as a claim, and a published leaderboard generated directly from
committed per-run result files.

# Statement of need

Published prompt-injection results are difficult to compare. Numbers are
reported at different attack budgets, on different agent surfaces, with and
without deployment safeguards, and at attempt level or scenario level; the same
model can span a very wide range depending only on which of these is chosen.
Vendor-published figures often benchmark the vendor's own models without
safeguards against competitors' production endpoints. Meanwhile the public
per-model tables that do exist are static artefacts of a paper and are not
refreshed as new models ship.

The gap this software addresses is not a shortage of measurements but a shortage
of *reproducible* ones. Large red-teaming studies produce the most authoritative
numbers available, but a study involving hundreds of human participants cannot
be re-run by a third party who wants to check a result or measure a newly
released model. `dspy-security-bench` is designed so that a single researcher
can produce a comparable measurement for a new model in a few hours and for a
few dollars of API spend, and so that anyone can audit the resulting number
against the raw per-task results committed alongside it.

The software targets three groups: researchers who need a controlled harness for
agentic injection experiments; practitioners choosing a base model for a
tool-using agent, who need to know that this property is not implied by
capability benchmarks; and engineering teams who want a regression gate, for
which the package ships a `scan` command that evaluates an arbitrary agent and
emits SARIF with OWASP LLM01, NIST AI 100-2 and MITRE ATLAS mappings.

# Design

Three decisions shape the implementation.

**The protocol is a frozen, hashed contract.** Suites, attack, agent scaffold,
decoding parameters and the exact task list live in a single YAML file whose
hash is recorded in every result. Changing anything under that block invalidates
existing rows rather than silently making them incomparable.

**Both axes are always reported.** Every result records task utility alongside
attack-failure rate. This is necessary rather than decorative: an agent that
accomplishes nothing also fails to accomplish the attacker's goal, so a security
figure without a utility figure cannot distinguish a robust model from an
ineffective one.

**Uncertainty is treated at the right level.** Each configuration is run
multiple times, but at temperature 0 those repeats are technical replicates —
in practice nearly all of them return identical results. Confidence intervals
are therefore produced by a cluster bootstrap over task pairs rather than over
pooled repeats, which would otherwise understate every interval. A result is
published as a *confirmed* claim only when its interval lies entirely within one
robustness band and that band is stable across repeats; otherwise it is
published as *provisional*, with its number, and no band asserted.

The harness is framework-agnostic: agents built with DSPy [@khattab2024dspy] are
supported directly, and any other agent can be measured through a generic
adapter.

# Limitations

The measurement is deliberately narrow and should be read as a lower bound on
attackability rather than a robustness guarantee. It uses fixed attack templates
rather than attacks re-optimised against each target, a single attempt per task
pair, and one agent surface. Published work shows each of these choices can
change the resulting figure substantially. These limitations are documented in
the repository alongside the results.

# Acknowledgements

This work builds directly on AgentDojo [@debenedetti2024agentdojo] for its task
environments and functional attack-success checks, and on DSPy
[@khattab2024dspy] for the agent implementation used by the default scaffold.

# References
