# Project governance

DSPy Security Bench is an independent open-source project maintained by Imran
Ahamed (`@immu4989`). The maintainer sets releases, protocol versions, security
policy, repository access, and the final merge decision.

## Decision principles

- Preserve reproducibility, synthetic-data safety, and honest uncertainty.
- Keep security, mission utility, and evidence provenance distinct.
- Prefer functional outcomes at instrumented tool boundaries over LLM judges.
- Never imply government endorsement, certification, compliance, or an ATO.
- Accept valid negative results and disclose benchmark limitations.

Material protocol changes begin with an issue or RFC, identify compatibility
and remeasurement costs, add tests and documentation, and receive maintainer
review. Security fixes may be developed privately and released without a public
RFC. Routine bug fixes and documentation changes use normal pull-request review.

## Evidence and conflicts

Community evidence is accepted for recomputability, not for favorable scores.
Submitters must disclose relationships that could materially affect evaluation
or procurement claims. Maintainer-authored reference agents are always labeled
as scorer fixtures and excluded from community model rankings.

## Becoming a maintainer

Sustained contributors may be invited after demonstrating sound technical
judgment, respectful review, and care with safety and measurement claims. Access
is least-privilege and may be removed when inactive or when project security
requires it.
