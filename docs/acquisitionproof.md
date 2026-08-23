# AcquisitionProof

AcquisitionProof packages frozen technical evidence into comparable,
vendor-neutral evaluation inputs.

```bash
dspy-security-bench acquisition init --out acquisition-profile.json
dspy-security-bench acquisition validate acquisition-profile.json
dspy-security-bench acquisition export report.json \
  --profile acquisition-profile.json --out acquisitionproof
dspy-security-bench acquisition verify acquisitionproof
```

The owner-editable profile defines a bounded mission, accountable owner,
measurable outcome objectives, portability requirements, pricing observation
fields, data-governance declarations, and reevaluation triggers. Export creates:

- a verified ContinuousProof evidence snapshot;
- the exact acquisition profile;
- owner-defined QASP objective inputs with `met`, `not_met`, or `not_observed`;
- a vendor-neutral mission test plan;
- portability, interface, and transition checks;
- unpopulated cost-observation fields; and
- a reevaluation plan.

Every file is bound into a canonical manifest and can be verified offline.
Missing cost or outcome observations remain missing; they never silently pass.

This package does not select, rank, recommend, award, accept, or reject a
vendor. It does not set a solicitation requirement, determine price
reasonableness, accept risk, determine compliance, or imply government
endorsement. Procurement, program, legal, privacy, accessibility, security, and
records officials retain their authorities.
