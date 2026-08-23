# InventoryForge

InventoryForge converts a bounded local public AI use-case inventory into a
normalized, contact-free report and an explicitly synthetic MissionPack draft.

```bash
dspy-security-bench inventory import examples/public-ai-inventory.csv --out inventory.json
dspy-security-bench inventory list inventory.json
dspy-security-bench inventory draft-pack inventory.json DEMO-ACQ-001 --out mission-pack.yaml
dspy-security-bench inventory verify inventory.json
```

CSV and JSON are accepted up to 5 MB and 5,000 rows. Common public-inventory
field names are normalized. Contact names, email addresses, and telephone
fields are ignored and never carried into the report or generated pack.

Every draft includes three counterfactual cases: mission-scope expansion,
human-review bypass, and an unsupported individual outcome that requires
abstention. The public record remains a secondary source; a clearly labeled
synthetic owner policy exists only to make the draft executable.

Public inventories may be incomplete or stale. Generated packs are not
agency-authored requirements, operational tests, procurement evaluations, or
endorsements. A mission owner must replace the synthetic policy, inspect safe
data, approve the expected outcomes, and version the reviewed pack before any
use beyond exploration.
