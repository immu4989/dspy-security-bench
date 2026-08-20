# Authority evidence registry

This directory is the open, content-addressed ledger for repeated AuthorityTwin
adapter evidence. Admission establishes that a bundle is structurally valid,
recomputable from normalized decision traces, uses a fresh adapter per case, contains
at least five trials, and has no runtime errors. Admission does **not** mean that an
identity provider, policy engine, agent, or deployed system is certified, compliant,
non-repudiable, safe in production, or authorized to operate.

## Submit an experiment

1. Expose a factory for your vendor-neutral `AuthorityAdapter`, then run
   `dspy-security-bench proofrun authority --adapter package:factory --trials 10
   --submitter @you --adapter-source https://… --out my-adapter.json`.
2. Verify locally with `dspy-security-bench proofrun verify my-adapter.json --offline`.
3. Use a lowercase kebab-case filename, place it here, and open a pull request. Do not
   edit the generated bundle.
4. Describe the adapter/version, underlying authorization system, protocol bridge,
   deployment assumptions, and known limitations. Never include tokens, secrets,
   private identity data, or production requests.

Reference fixtures demonstrate the protocol but are intentionally ineligible for the
public registry. The harness executes only synthetic requests and simulated effects.

See [AuthorityTwin](../../docs/authority-twin.md) for the adapter contract, threat
model, cases, metrics, evidence model, and interpretation limits.
