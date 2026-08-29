# CollectiveGuard community evidence registry

This directory is a content-addressed commons for provenance-aware evidence
about multi-agent containment. CI recomputes the embedded CollectiveGuard v1
structural analysis, v2 source coverage, every event provenance classification,
and the outer bundle digest without network access.

Admission means only that the submitted structural record and declared
provenance recompute. It does not authenticate a source or attester, prove trace
completeness, certify safety or compliance, establish government endorsement,
or authorize operation. A violation result may be eligible; a clean-result
claim is eligible only when every required source is complete and every event
has direct observed or attested provenance.

## Submit interoperable evidence

1. Create and inspect a content-free v2 scenario:

   ```bash
   dspy-security-bench collective plane init \
     --profile hardened-complete --out collective-v2.json
   dspy-security-bench collective plane run collective-v2.json \
     --json-out collective-v2-report.json --fail-on-insufficient
   ```

2. Replace the synthetic source digests and event observations through an
   EvidenceBridge manifest. The manifest accepts identifiers, timing, field-name
   coverage, hashes, and provenance classifications—not prompts, messages,
   chain-of-thought, credentials, tool arguments/results, or exploit payloads.

   ```bash
   dspy-security-bench collective bridge from-v2 collective-v2.json \
     --adapter-profile runtime-neutral-json --out evidence-bridge.json
   dspy-security-bench collective bridge build evidence-bridge.json \
     --out collective-v2.json
   ```

3. Build and verify the public bundle:

   ```bash
   dspy-security-bench collective plane bundle collective-v2.json \
     --submitter @you \
     --runtime "your-runtime@version" \
     --source-repository https://github.com/owner/repo/tree/COMMIT \
     --deployment-class enterprise \
     --known-gap "describe any sampling or source gap" \
     --out your-runtime.json
   dspy-security-bench collective plane verify your-runtime.json
   ```

4. Inspect the exact public bytes, use a lowercase kebab-case filename, and open
   a pull request. Pin the source repository to the tested commit and disclose
   sampling, clock, adapter, trust-root, and redaction limitations.

`reference-runtime.json` is a fictional, deterministic format example—not a
production result or a community endorsement.
