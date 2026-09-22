# Fictional scan review — no model was executed

These six invented cases teach evidence replay and matched comparison. They are
not AgentDojo benchmark results, a model ranking, or deployment evidence.

Open review.html in a browser; it needs no server or internet connection.
From this directory, run:

```sh
dspy-security-bench scan verify before.json
dspy-security-bench scan verify after.json --fail-on-shortfalls
dspy-security-bench scan compare before.json after.json --verify comparison.json
dspy-security-bench scan compare before.json after.json --fail-on-regression
```

Expected exit codes: 0, 1, 0, 1 respectively. Valid evidence is not the same as
meeting requirements. Both security (4/6) and utility (5/6) totals stay unchanged,
but each axis has one newly failing case. Improvements elsewhere do not cancel it.

All identifiers and outcomes are fictional. Digests demonstrate reproducibility,
not execution authenticity. Do not submit these files as measured public results.
