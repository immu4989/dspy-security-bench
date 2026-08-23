# TraceProof community evidence registry

This directory is the open, content-addressed ledger for privacy-bounded
TraceProof experiments. Admission means the sanitized evidence, deterministic
findings, optional MCP authorization probe, and bundle digest all recompute
under the frozen protocol. A failing security result can be admitted when the
evidence is valid.

Admission does **not** establish trace completeness, independent execution,
system safety, protocol certification, compliance, government endorsement, or
an authorization to operate. Bundles are self-attested until an independent
provenance tier is added. Never submit raw OTLP, prompts, responses, tool
arguments, credentials, identifiers, production requests, or regulated data.

## Submit an experiment

1. Generate content-free telemetry with the
   [runtime kit](../../docs/traceproof-runtime-kit.md), or sanitize an operator-
   reviewed OTLP JSON/JSONL export locally.
2. Recompute the TraceProof report and, for MCP over HTTP, the frozen
   authorization probe:

   ```bash
   dspy-security-bench trace import raw-otlp.json --out trace-evidence.json
   dspy-security-bench trace analyze trace-evidence.json --out trace-report.json
   dspy-security-bench trace mcp analyze trace-evidence.json --out mcp-report.json
   ```

3. Review the sanitized files, then build and verify the content-addressed
   bundle:

   ```bash
   dspy-security-bench trace bundle trace-evidence.json trace-report.json \
     --mcp-report mcp-report.json \
     --submitter @you \
     --runtime "your-runtime@version" \
     --source-repository https://github.com/owner/repo/tree/COMMIT \
     --out your-runtime.json
   dspy-security-bench trace verify-submission your-runtime.json
   ```

4. Use a lowercase kebab-case filename, place the generated JSON here, and open
   a pull request. State what was instrumented, the collection boundary, known
   gaps, and whether the source URL is pinned to the exact tested commit.

Maintainer demos, the redaction challenge, and the reference lab demonstrate
the protocol but are intentionally ineligible for the public ledger.
