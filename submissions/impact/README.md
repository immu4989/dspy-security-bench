# RepeatTwin community submissions

This directory accepts independently inspectable RepeatTwin result bundles.
Contributors run their own agent, preserve every raw trial, create a
content-addressed bundle, and open a pull request. CI recomputes all published
statistics and rejects modified or underpowered bundles without making a model
call. Eligible bundles must also record a fresh agent instance for every case,
which the CLI does automatically from the supplied zero-argument factory.

## Submit a result

```bash
# 1. Run at least five complete trials. Ten is the recommended default.
dspy-security-bench impact repeat \
  --agent your_package.security:build_agent \
  --trials 10 \
  --json repeat.json

# 2. Add public attribution and a source/implementation URL.
dspy-security-bench impact submit-result repeat.json \
  --submitter "@your-github-handle" \
  --agent-source "https://github.com/you/your-agent" \
  --out submissions/impact/your-agent.json

# 3. Recompute the bundle before opening a pull request.
dspy-security-bench impact verify submissions/impact/your-agent.json
```

Do not edit generated JSON by hand: its canonical SHA-256 digest covers the
entire report. Use a filename containing only lowercase letters, digits, and
hyphens.

## What “verified” means

Offline verification confirms that the protocol identity, raw trials,
statistics, Wilson intervals, usage totals, and content hashes agree. The
submitter and execution environment are self-attested; a content hash is not
proof of who ran a model. Results remain scoped to the five frozen synthetic
ProcureBench pairs and are not safety or compliance certifications.
