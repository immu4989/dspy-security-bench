# TraceProof runtime reference lab

This local lab wires a fictional agent boundary to a real OPA decision service,
emits content-free OTLP/HTTP telemetry through a real OpenTelemetry Collector,
and analyzes the Collector file export with TraceProof and the frozen MCP
authorization probes.

Prerequisites: Docker Compose and `dspy-security-bench` installed on the host.

```bash
./examples/traceproof-runtime-lab/run.sh
```

The script preserves any previous `otlp.json` under a timestamped name, starts
the lab, waits for the synthetic agent, stops only the lab's Compose services,
and writes sanitized evidence, deterministic findings, SARIF, and an MCP probe
report under `examples/traceproof-runtime-lab/artifacts/`.

The lab pins OpenTelemetry Collector Contrib `0.159.0`, OPA `1.16.2`, and Python
`3.12.11-slim`. Version tags improve reproducibility but are not immutable image
digests; production adopters should verify and pin approved image digests in
their own supply-chain process.

All identities, resources, policies, and actions are fictional. The lab does
not process prompts, tool arguments, tokens, personal data, government data, or
production requests. It is integration evidence, not a product certification,
OPA or OpenTelemetry endorsement, compliance determination, or authorization
to operate.
