# Bring your own agent

`dspy-security-bench integrate` turns an existing Python agent repository into
a ProofRun target without requiring users to rewrite the benchmark harness. It
supports OpenAI Agents SDK, LangChain/LangGraph, Pydantic AI, CrewAI, Microsoft
AutoGen AgentChat, and an explicit callback bridge for MCP or custom loops.

## Five-minute path

From the repository that contains your agent:

```bash
pip install dspy-security-bench

# Detect a directly declared framework from pyproject.toml or requirements files.
dspy-security-bench integrate

# Or choose explicitly.
dspy-security-bench integrate --framework openai-agents --model gpt-5.6

# Check imports, fresh-agent construction, credentials, and workflow policy.
# This never invokes agent.run().
dspy-security-bench doctor
```

The command creates:

- `dspy_security_target.py`, a small factory users can review and customize;
- `.dspy-security-bench/integration.json`, a machine-readable preflight contract;
- `tests/test_dspy_security_target.py`, a zero-network fresh-instance check; and
- `.github/workflows/dspy-proofrun.yml`, a manually triggered, attestation-ready
  workflow pinned to the release engine.

Generated files are never overwritten unless `--force` is passed. The workflow
starts with `workflow_dispatch` only, avoiding unexpected model spend on every
pull request. Add automatic triggers only after choosing a budget, secret policy,
and branch-protection rule.

## Supported frameworks

| Framework | Command | Optional extra |
|---|---|---|
| OpenAI Agents SDK | `--framework openai-agents` | `dspy-security-bench[openai-agents]` |
| LangChain / LangGraph | `--framework langchain` | `dspy-security-bench[langchain]` |
| Pydantic AI | `--framework pydantic-ai` | `dspy-security-bench[pydantic-ai]` |
| CrewAI | `--framework crewai` | `dspy-security-bench[crewai]` |
| Microsoft AutoGen AgentChat | `--framework autogen` | `dspy-security-bench[autogen]` |
| MCP / custom loop | `--framework mcp --runner package.module:run_agent` | Existing client dependencies |

`[frameworks]` installs all five native SDK bridges. Most projects should
install only their existing framework's extra.

The current CrewAI dependency stack supports Python 3.10–3.13. The benchmark's
base package and other bridges continue to support Python 3.14; use a Python
3.13 environment when selecting the CrewAI extra.

The OpenAI bridge follows the official Agents SDK contract: Python callables
become `function_tool` objects, `Runner.run_sync` executes the loop, and
`final_output` becomes the benchmark answer. The framework adapters preserve
the same security invariant: they invoke the exact `BenchTool` callable supplied
by the live synthetic environment. Reimplementing or simulating a tool produces
invalid functional evidence.

## Custom and MCP-backed loops

MCP standardizes tool discovery and execution, but it does not define one
universal agent loop. Supply a callback instead:

```python
from dspy_security_bench.agents import AgentResult, BenchTool


def run_agent(
    query: str,
    tools: list[BenchTool],
    system_directive: str,
) -> str | AgentResult:
    # Pass these exact live callables into your MCP/client loop.
    # Do not replace them with mocks or copies.
    ...
```

Then scaffold it:

```bash
dspy-security-bench integrate \
  --framework mcp \
  --runner myapp.security:run_agent
dspy-security-bench doctor
```

Callbacks may be synchronous or asynchronous. Returning `AgentResult` preserves
an optional tool-call ledger and provider-reported usage; returning text supplies
only the final answer.

## What doctor checks

`doctor` itself performs no network calls, sends no prompts, and never invokes
`agent.run()`. Agent factories are expected to be side-effect free. It verifies:

1. the integration manifest and framework declaration;
2. the optional framework import and installation hint;
3. that the factory returns distinct agent instances with the required contract;
4. that the workflow has attestation permissions, the matching factory, and a
   versioned engine rather than `@main`; and
5. whether expected provider credentials exist locally, reported as warnings
   rather than exposing their values.

Use `dspy-security-bench doctor --json` in other developer tooling. A missing
local credential is a warning because the secret may exist only in GitHub.

## Framework documentation

- [OpenAI Agents SDK quickstart](https://developers.openai.com/api/docs/guides/agents/quickstart)
- [LangChain agents](https://docs.langchain.com/oss/python/langchain/agents)
- [Pydantic AI function tools](https://pydantic.dev/docs/ai/tools-toolsets/tools/)
- [CrewAI direct agent interaction](https://docs.crewai.com/en/concepts/agents)
- [AutoGen AgentChat agents](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/agents.html)

These integrations reduce wiring effort; they do not make five frozen synthetic
scenarios representative of deployment, independently authenticate a remote
provider response, or turn ProofRun into a safety or compliance certificate.
