# Bound supplied-tool calls within each benchmark task

**On main; not in the published v0.19.0 package.** A task-count budget bounds
how many task invocations are planned. It does not limit the work an agent can
perform inside one task. The optional cooperative tool budget adds that
separate limit at the `Agent` / supplied `BenchTool` boundary.

```yaml
limits:
  max_task_runs: 100
  max_tool_calls_per_task: 12
```

Or inspect a plan with:

```sh
dspy-security-bench scan --config .dspy-security-bench.yaml \
  --max-tool-calls-per-task 12 --plan-json budgeted-plan.json
```

These numbers are examples, not recommended operational limits. Choose them
with the task/tool owner. Review the plan before authorizing execution and use
its independent `report_sha256` pin when running the scan. Changing or removing
the tool limit changes the plan identity before agent construction.

## Admission semantics

- The optional integer limit is inclusive, from 1 through 10,000, and resets
  for every `agent.run` call—including auxiliary benchmark tasks.
- It counts invocations of the supplied wrapped tools. An invocation consumes
  one admission **before** the original callback starts. A callback that raises
  still consumes its admission. Calls beyond the cap never reach that callback.
- All supplied tools in a task share one counter. A lock makes admission exact
  for cooperative thread-based parallel invocations.
- Exhaustion raises `AgentToolBudgetError`. Even if an agent catches that tool
  error and returns a final answer, the wrapper rejects the task as incomplete.
  In a scan, this is an execution error (exit 2), not a safe score, utility
  failure, or passing non-blocking gate. No complete scan evidence is emitted.
- Wrapped tool sessions close after the agent returns or raises. Captured tool
  references cannot execute new callbacks after the run. Returning while an
  already-admitted callback is still running is also an incomplete execution.

The wrapper passes the real tools through; it does not replace environment
effects with invented traces. In-memory schema copies keep an agent's metadata
edits from changing the original supplied tools.

## What this does not control

This is **not a sandbox or cancellation system**. It does not stop a running
callback, roll back prior side effects, or kill a hung provider. It does not
limit tokens, dollars, provider requests/retries, time, callback-internal network
operations, or tools/network access an agent creates independently. A tool
invocation may itself perform many actions. An emitted but malformed/unknown
model tool request that never invokes a supplied `BenchTool` is not an admitted
tool call. Hostile code with process access can bypass cooperative wrappers.

Run only reviewed agents against authorized test tools. Use deployment-owned
network, process, resource, credential, and transaction controls for stronger
containment. Agents using background or process-based tool execution must await
their work and preserve the provided tool boundary; this adapter is not a
distributed budget authority.

## Preserve comparability

Configured scans use measurement protocol
`tool-budgeted-binary-observations-v3` and retain an exact
`execution_controls.max_tool_calls_per_task` value in their frozen scope.
Unconfigured scans keep `complete-binary-observations-v2` unchanged. Old v1/v2
evidence remains replayable and cannot claim this additional control.

Scope-bound baselines, matched comparisons, and repeated studies require the
same budgeted protocol **and the same limit**. Do not relabel old evidence or
delete the control field to make scopes match. Recollect an owner-approved
baseline if the execution policy changes. The generic `scan-evidence-v1`/v2
format version still describes gate serialization, not execution controls.

The source code and runtime implementing a declaration are not authenticated by
the evidence format. Retain reviewed code/dependency identity and execution
provenance separately. See the [upgrade guide](scan-upgrade-guide.md).

## Wrap a custom agent directly

```python
from dspy_security_bench.agents import ToolBudgetAgent

bounded_agent = ToolBudgetAgent(my_agent, max_tool_calls_per_task=12)
result = bounded_agent.run(query, supplied_tools, system_directive=policy)
```

Direct library use does not automatically create scan scope/provenance. Do not
label hand-written reports as budgeted measurements merely because this wrapper
was imported. Use the scan path when you need its retained scope binding.
