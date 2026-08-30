# AssuranceGraph public reproduction exchange

This directory is a strict, non-ranking metadata index for safely public,
independently reproducible AssuranceGraph reports. Both favorable and
unfavorable outcomes are useful. Admission validates metadata structure,
content digests, immutable source revisions, and the registry digest; it does
not authenticate external observations or endorse a system, vendor, model,
organization, profile, or deployment.

## Submit a report

1. Use synthetic or appropriately sanitized evidence. Never publish credentials,
   private prompts or reasoning, personal or regulated records, production
   telemetry, live-target identifiers, weaponized exploit payloads, protected
   infrastructure details, or unpublished vulnerabilities.
2. Recompute locally:

   ```bash
   dspy-security-bench assure verify assurance-report.json \
     --evidence-root ./publishable-evidence
   dspy-security-bench assure federal-pack assurance-report.json \
     --evidence-root ./publishable-evidence --out-dir review-pack
   dspy-security-bench assure federal-verify review-pack \
     --evidence-root ./publishable-evidence
   ```

3. Publish the report and exact publishable evidence at an immutable commit.
   Add one metadata entry to `index.json`, preserve every unfavorable outcome
   and known gap, reseal the registry, and open a pull request:

   ```bash
   dspy-security-bench assure exchange-seal index.json --out index.sealed.json
   dspy-security-bench assure exchange-verify index.sealed.json
   ```

   Review the exact diff before replacing `index.json`; no submitted repository
   code is auto-executed.
4. Independent reproducers add their identity label, immutable source revision,
   canonical report digest, time, and known gap to `independent_reproductions`.
   The reproduced digest must match the indexed report. A reproduction is a
   recomputation claim, not validation of the truth or completeness of the
   underlying observation.
5. Run `dspy-security-bench assure exchange-verify` before submitting.

Entries can be marked `stale`, `withdrawn`, or `superseded`; history is not
silently rewritten. The exchange does not calculate a leaderboard or universal
safety score. Accountable owners retain every deployment, procurement, risk,
response, and authorization decision.
