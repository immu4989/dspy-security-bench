# Agent results: required outputs versus optional telemetry

These checks are **on main after v0.19.0**, not in the published v0.19.0 wheel.
Install a reviewed source revision and retain its dependency lockfile.

An `AgentResult` dataclass does not validate its annotations at construction.
Benchmark adapters and mission runners call `validate_agent_result` before
accepting its required fields. Custom callbacks can also return text directly.
`CallbackAdapter.run` and `await CallbackAdapter.arun` apply the same checks
after completion; exceptions and cancellation are not coerced into answers.
See [async callback ownership and context](integrations.md#async-callbacks-in-notebooks-and-services)
before using loop-bound clients or futures. Benchmark runners remain synchronous.

| Field | Accepted value | Invalid-value handling |
| --- | --- | --- |
| `final_answer` | Explicit text, including an intentional `""` | Execution error; never substitute an empty answer for `None` |
| `tool_calls` | A list, empty by default, of `ToolCall` objects | Execution error; do not use `None` for an absent trace |
| Each `ToolCall` | Nonblank text name, dictionary arguments, text result | Execution error; no implicit stringification or default arguments |
| Optional `usage` | Supported valid fields from a dictionary | Unknown/absent fields, not a task failure or invented zero |

```python
from dspy_security_bench.agents import AgentResult, normalize_usage, validate_agent_result

result = AgentResult(final_answer="Declined", usage={"total_tokens": 17})
validate_agent_result(result)  # Returns the same object; raises AgentResultError if invalid.
telemetry = normalize_usage(result.usage)  # A new dictionary; input is not changed.
```

`normalize_usage` accepts nonnegative integer `prompt_tokens`, `completion_tokens`,
and `total_tokens`, plus finite nonnegative `estimated_cost_usd`. Booleans,
strings, fractional counts, negative values, nonfinite/overflowing costs, and
unsupported fields are omitted. Zero remains a reported zero. Missing totals
are not inferred from other fields. Procurement, IncidentTwin, and MissionPack
use this same normalizer; it does not prove billing accuracy or completeness.

## How failures are recorded

Generic and DSPy AgentDojo runs stop with a separate execution error, without a
completed scan gate or evidence file. See the [v4 scope migration](scan-upgrade-guide.md)
before comparing new scans with archived measurements.

The generic AgentDojo bridge also closes supplied tool handles at task exit and
rejects unfinished callbacks or caught harness/defense failures independently of
the agent's optional ledger. Explicit runtime domain-error text remains normal
feedback. See [generic tool lifetime](integrations.md#generic-agentdojo-tool-lifetime)
for `AgentToolExecutionError`, cancellation behavior, and cooperative limits.

The reference LiteLLM loop requires one completed assistant turn and explicit
text before producing a result. Missing answers, unfinished generations, pending
final-step tools, and supported detection of native error states cannot become
empty scored answers. Tool-batch metadata is checked before execution, while
earlier instrumented effects remain. See [LiteLLM admission and SDK limits](integrations.md#litellm-completion-and-tool-turn-admission).

The built-in OpenAI Agents bridge additionally requires explicit empty
interruption state and text `final_output`. Pending approval is incomplete
execution even if a text value is present; it is not automatically approved or
resumed. See [native bridge details](integrations.md#openai-agents-result-completeness).
This check does not claim to detect every incomplete state in every framework.

The built-in LangChain bridge requires a terminal assistant message with no
pending/invalid tool calls and no graph interruption. It extracts explicit text
blocks, never user/tool messages or reasoning metadata. See
[LangChain attribution](integrations.md#langchain-final-answer-attribution) for
the supported state shape and custom-callback migration path.

The built-in AutoGen bridge accepts terminal text or a tool summary from the
configured agent, with explicit single-agent stop state. Handoffs, user messages,
thoughts, and arbitrary objects are not scored answers. See
[AutoGen execution and attribution](integrations.md#autogen-execution-and-final-answer-attribution)
for the corrected default name, native tool metadata, and iteration-limit semantics.

The Pydantic AI bridge requires explicit text in `AgentRunResult.output` before
reading optional usage. Deferred approval/external-call objects and structured
results are not implicitly serialized. See [Pydantic AI completion rules](integrations.md#pydantic-ai-text-output-and-deferred-work).

All five native bridges also retain supplied-tool failures independently of SDK
recovery. Non-text tool returns remain invalid results; caught callback failures
or unfinished callbacks are execution errors. Retained callbacks close after the
native run, without rolling back earlier effects or cancelling admitted work.
See [native tool lifetime and limits](integrations.md#native-supplied-tool-failures-and-lifetime).

Procurement, IncidentTwin, and MissionPack record `invalid_agent_result` for a
malformed result and `agent_execution_error` for other ordinary agent exceptions.
Neither qualifies for mission completion. Already instrumented actions and harms
remain in the report: a bad return does not undo a disclosure or other side effect.
These fields omit raw exception messages; outputs emitted by agents/dependencies
and report fields containing normal task content are not thereby redacted.

`TraceRecordingAgent` records an error agent span for a malformed result, retains
preceding tool spans, and re-raises `AgentResultError`. Direct `ToolBudgetAgent`
use also validates results after closing supplied tools and checking exhaustion
or unfinished callbacks. Neither wrapper rolls back completed effects.

## Limits and historical evidence

The shape check is not recursive JSON Schema validation, a trace-authenticity or
completeness test, a resource bound, a sandbox, or a detector of conversions and
errors hidden inside an SDK. Empty text is valid input to the scorer, not proof
of successful work. Outcome scoring still uses the benchmark's actual rules.

Frozen mission scenarios and scoring formulas are unchanged. Saved evidence is
not rewritten or upgraded by replay, including historical telemetry extensions
and error text. Preserve older artifacts and their producer revisions; recapture
when you need evidence from the new admission boundary. A successful offline
replay does not prove which runtime checks executed.
