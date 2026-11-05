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

# Only after reviewing and trusting imports and constructors:
# check imports, fresh-agent construction, credentials, and workflow policy.
dspy-security-bench doctor
```

With a reviewed **source install on main**, first run
`dspy-security-bench doctor --manifest-only` to inspect declarations without
importing the target. That mode is not in the published v0.19.0 package; see
[the declarative preflight section](#inspect-before-executing-target-code).

The command creates:

- `dspy_security_target.py`, a small factory users can review and customize;
- `.dspy-security-bench/integration.json`, a machine-readable preflight contract;
- `tests/test_dspy_security_target.py`, a fresh-instance check that constructs
  trusted factories without invoking their run methods; and
- `.github/workflows/dspy-proofrun.yml`, a manually triggered workflow declaring
  attestation permissions and a release-version reference.

Generated files are never overwritten unless `--force` is passed. The workflow
starts with `workflow_dispatch` only, avoiding unexpected model spend on every
pull request. Add automatic triggers only after choosing a budget, secret policy,
and branch-protection rule.

Release tags can move: replace the engine reference in both manifest and workflow
with a reviewed full commit SHA when immutable pinning is required. Doctor warns
on version tags; local checks do not prove hosted permissions or provenance.

## Preview and protect an existing project

The all-file preview and conflict gate are **on main after v0.19.0**. Before
generating files, inspect the proposed paths and changes:

```bash
dspy-security-bench integrate --framework langchain --dry-run
dspy-security-bench integrate --framework langchain --dry-run --json
```

For MCP/custom targets, also supply `--runner package.module:run_agent`. Automatic
framework detection works in preview mode too. No files or directories are
created by `--dry-run`, even when the requested root does not exist (use an
explicit framework in that case). The generated Python is parsed, not imported
or executed. Preview does not check SDK availability or prove the adapter can run.

Each selected file has one action:

| Action | Meaning |
|---|---|
| `create` | No directory entry exists at the proposed file path. |
| `unchanged` | Existing bytes exactly match the proposed bytes; leave them untouched. |
| `conflict` | Existing bytes differ; **all scaffold writes stop**, including missing files. |
| `replace` | Existing bytes differ and `--force` explicitly permits replacement. |

JSON uses `mode: "scaffold_preview"`, an agent import string, `has_conflicts`, and
`files` with relative paths, actions, byte lengths, and existing/proposed SHA-256
fingerprints. It omits file contents and model values, but filenames and hashes
are not anonymized. It is an informational snapshot, **not a saved plan that can
be submitted for execution**. Application recomputes a fresh plan from the same
CLI options and rechecks its observed file bytes before writing.

Both preview and application return 0 for a conflict-free result, 1 for existing
content conflicts, and 2 for invalid input or filesystem failure. Repeating an
identical scaffold leaves files and modification times unchanged. Previously,
different existing files were skipped independently; a rerun could therefore
combine an old adapter with newly generated metadata. The conflict gate no longer
allows that mixture. Review existing customizations and reconcile manually, pick
another target module, or deliberately replace the selected generated files:

```bash
# First commit or back up work you intend to retain.
dspy-security-bench integrate --framework langchain --force --dry-run
# Run only after reviewing the preview and deciding to replace those files.
dspy-security-bench integrate --framework langchain --force
```

`--no-workflow` and `--no-test` remove those files from the plan; they are neither
inspected nor changed. `--force` does not bypass link, special-file, collision,
syntax, or size checks. Existing destinations must be regular non-linked files
of at most 1 MB each. The owner-selected root is resolved once (an intentional
root alias is supported); observed links/reparse points and nondirectory parents
below it are rejected. Identifiers reject Python keywords, normalization-changing
names, and reserved portable destination names. Colliding generated paths fail
before writes, callback modules cannot collide with generated modules, and aliased
callback imports avoid generated-name shadowing.

New files use exclusive creation. Forced replacements stage complete bytes in a
fresh sibling file before using
[`os.replace`](https://docs.python.org/3/library/os.html#os.replace); they do not
truncate the old file in place or change its hard-linked siblings. New/replacement
files use restrictive creation modes, subject to platform ACLs; original file
metadata is not preserved and no backup is made automatically. The integration
manifest is ordered last, but **this is not an all-or-nothing transaction** or a
manifest-based completion protocol. Existing unchanged manifests may remain
throughout a run. Late I/O failure can leave created/replaced files or directories;
exit 2 reports completed and attempted relative paths. Review them before retrying.
There is no rollback, crash-durability guarantee, concurrent-writer protection,
or OS sandbox. Keep project paths stable and owner-controlled.

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

## Inspect dependency declarations before generating files

The structured detector and read-only inventory are **on main after v0.19.0**.
With a reviewed source install, run:

```bash
dspy-security-bench integrate --root . --detect
dspy-security-bench integrate --root . --detect --json
```

Neither command generates files, imports project code, installs packages, calls
build backends, expands environment variables, or fetches dependency URLs. JSON
contains `schema_version: 1`, `mode: "declarations_only"`, and a
`detected_frameworks` list with each framework key, label, and relative
`declarations` filenames. Exit 0 means the inventory was read successfully,
including an empty or ambiguous inventory; exit 2 means inspection failed.
Errors go to stderr without source values. `--json` requires `--detect` or
`--dry-run`; the latter emits the separate scaffold-preview format above.

Detection now parses declaration fields instead of searching entire files:

- `pyproject.toml`: project dependencies, optional extras, dependency groups
  (including validated group references), and Poetry dependency/dev/group tables.
- `Pipfile`: package, development, and custom package categories, excluding
  sources, scripts, interpreter requirements, and Pipenv settings.
- `requirements.txt` and root `requirements-*.txt`: named PEP 508 requirements,
  extras/markers, named direct URLs, continuations, hashes, and local `-r`
  includes. Comments, index settings, and `-c` references are not dependencies.
- `setup.cfg`: `options.install_requires` and `options.extras_require`.
- `setup.py`: literal dependency lists/tuples and extras dictionaries in calls
  associated with top-level `setuptools`/`distutils.core` setup imports. Parsing
  syntax does not execute the file or prove which calls actually run.

This follows the declaration boundaries described by
[PyPA project metadata](https://packaging.python.org/en/latest/specifications/pyproject-toml/),
[dependency groups](https://packaging.python.org/en/latest/specifications/dependency-groups/),
[pip requirements](https://pip.pypa.io/en/stable/reference/requirements-file-format/),
[Poetry](https://python-poetry.org/docs/pyproject/#dependencies-and-dependency-groups),
and [Pipenv](https://pipenv.pypa.io/en/latest/pipfile.html). It is a documented
static subset, not a replacement for those tools' complete configuration validation.

Optional/development declarations and inactive environment markers **all count**;
markers are not evaluated against the current machine. Thus the inventory does
not prove installation, active use, version compatibility, or successful execution.
Lockfiles and transitive packages are excluded. For example, a comment mentioning
CrewAI beside a real LangGraph requirement selects only LangChain; a CrewAI extra
beside that requirement makes automatic selection ambiguous and requires
`--framework langchain` or another explicit choice.

Dynamic metadata, nonliteral setup arguments, and unnamed local/archive/VCS
requirements cannot supply a complete static inventory: choose `--framework`
explicitly. Normal doctor warns when these unsupported declarations prevent full
inspection and uses the framework from the explicit integration manifest; it
still runs its other checks before loading trusted factories. Malformed or unsafe
inputs remain failures. Manifest-only doctor does not inspect dependencies at all.

Inputs must be UTF-8, regular non-linked files under a stable owner-selected root.
Limits are 1 MB per file, 4 MB total, 32 unique files, 4,096 root directory entries,
4,096 characters per requirement, and 20,000 nodes/50 levels for parsed TOML or
Python syntax. Include cycles, traversal, absolute/remote `-r` paths, and observed
linked ancestors fail; include paths use portable forward slashes. Constraints
are never followed through `-c`. A file independently discovered by the root
requirements wildcard is still read and validated, but contributes no dependency
evidence if it is only used as a constraint; an explicit `-r` can also use it as a
requirement file. These limits are not an OS sandbox or a filesystem race defense.

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

Callbacks must return one of those types, including after awaiting completion;
unsupported objects are execution errors, not stringified answers. A valid
`AgentResult` contains an explicit text `final_answer` (an intentional `""` is
allowed) and a list of `ToolCall` objects with nonblank text names, dictionary
arguments, and text results. Omit the trace to use its default empty list, not
`None`. You can call `validate_agent_result` from `dspy_security_bench.agents` in
your adapter's own tests. The check neither authenticates self-reported traces
nor recursively validates tool arguments. Optional malformed usage telemetry
does not invalidate an otherwise valid result. See the
[scan upgrade guide](scan-upgrade-guide.md) before reusing an older baseline.

The [shared result and telemetry contract](agent-result-contract.md) also covers
Procurement, IncidentTwin, MissionPack, and direct tracing/budget wrappers.
Mission runners retain only supported valid usage fields; `normalize_usage` is
available from `dspy_security_bench.agents` for custom adapters' own tests.

The reference LiteLLM agent reports a run-level token/cost total only if that
field is valid on **every returned completion response**, including its forced
final-answer response. Missing/invalid fields and nonfinite accumulated cost
remain absent, not zero or a partial sum. Other complete fields can still be
reported. **On main after v0.19.0**, ordinary exceptions from optional usage/cost
getters make the affected quantities unknown without preventing response or
tool execution. Interrupts and cancellation still propagate, as do provider,
tool, and required-response errors; blocking getters are not time-limited.
These are SDK-exposed estimates, not billing reconciliation;
unreported SDK retries, tool execution costs, and provider-side work are not
included. Extraction reads the response's token fields and existing
`_hidden_params["response_cost"]` only; it does not fetch prices or calculate
missing cost. SDK defaults or computed fields cannot be distinguished from
provider observations after that distinction is lost. Custom agents own the
completeness of usage they supply.

## Tool schema fidelity at the generic boundary

**On main after v0.19.0**, the AgentDojo-to-`BenchTool` bridge snapshots the entire
argument schema emitted by the runtime's Pydantic model. It preserves `$defs`
and `$ref`, nested constraints, enums/unions, aliases, defaults, descriptions,
and root-level keywords such as `additionalProperties`. It does not flatten
references or reconstruct a schema from only `properties` and `required`.
When Pydantic omits `required` for a default-only tool, those arguments remain
optional; the bridge no longer declares every model field mandatory.

For example, an order tool with nested line items keeps the definitions for
each item's allowed fields and quantity bounds. A count tool with `count=2`
can still be called with `{}`, and the live runtime applies its default. The
bridge does not execute tools while inspecting schemas. This follows
[Pydantic's JSON Schema representation](https://pydantic.dev/docs/validation/latest/concepts/json_schema/)
and [AgentDojo's runtime validation boundary](https://agentdojo.spylab.ai/concepts/functions_runtime/).

`BenchTool.openai_schema()` returns a deep, detached copy of nonempty parameters.
Changes to nested definitions/defaults in that exported dictionary do not alter
the source tool or another export. The reference LiteLLM loop also gives each
completion round a fresh copy, so provider-side normalization cannot silently
rewrite subsequent rounds or later evaluations. The existing empty-`{}`
`BenchTool.parameters` shorthand still exports an empty object-argument schema.

**Scope:** this is schema preservation, not a new argument validator, provider
compatibility certification, immutable tool sandbox, or semantic equivalence
proof. AgentDojo continues to validate/coerce arguments and apply defaults under
its own rules. Custom callbacks retain their existing validation behavior.
Providers may reject unsupported schema features. The five built-in native SDK
bridges currently derive signatures from primitive property types; they do
**not** preserve the full source schema's nested constraints, references, enums,
or unions. This change does not repair those independent SDK conversions.
Use a schema-aware custom callback and validate your integration when those
features matter; do not assume cross-framework schema equivalence.

Offline regressions compare real generated schemas, resolve local recursive
references, exercise valid/invalid nested arguments in the real AgentDojo
runtime, check live effects/defaults, and simulate mutation across LiteLLM
rounds and repeated runs. They make no provider requests. Schema changes can
affect model behavior: record the producer version and re-run affected baselines
instead of comparing pre-fix and post-fix results as identical configurations.
No historical scores are rewritten and no measured score improvement is claimed.

## LiteLLM completion and tool-turn admission

**On main after v0.19.0**, the reference agent accepts exactly one non-streaming
assistant choice. A final answer requires `finish_reason="stop"`, explicit string
content (including `""`), and no pending tool or legacy function call. Missing or
non-text content is never replaced with an empty answer. Truncated/filtered
output, streaming chunks, alternative choices, and unsupported termination states
are execution errors. A textual refusal with an otherwise completed state is
still scored normally; this is not a check of answer quality or truthfulness.

The forced-final request after `max_iters` uses the same checks and never executes
new calls. During normal rounds, tool calls require `finish_reason="tool_calls"`,
text-or-null assistant content, named functions, and nonblank IDs unique within
the returned batch. The complete batch's metadata is admitted before any of its
tools run. Provider-specific tool extensions are preserved. Malformed JSON
arguments and unknown named functions retain the existing tool-error feedback;
they do not execute a default action. A supplied tool must return text, not an
object to stringify. Already completed actions are not rolled back on failure.

LiteLLM's [output contract](https://docs.litellm.ai/docs/completion/output) exposes
normalized finish reasons and sometimes the original value in
`choice.provider_specific_fields.native_finish_reason`. A normalized `stop` alone
can hide an error: the pinned SDK maps reasons such as `ERROR`, `network_error`,
and `MALFORMED_FUNCTION_CALL` to it. When an original reason survives, this adapter
accepts only `stop`, `stop_sequence`, `end_turn`, `COMPLETE`, `eos_token`, `eos`, or
`STOP`; tool turns also accept `tool_calls` and `tool_use`. Unknown reasons require
explicit compatibility work, not an optimistic fallback. The
[function-calling example](https://docs.litellm.ai/docs/completion/function_call)
illustrates the separate tool-execution and final-response turns.

These checks examine **SDK-returned state**, not raw provider provenance. SDKs may
insert defaults (including roles, stop reasons, and tool IDs) or discard native
state before the adapter sees it. The boundary cannot recover those distinctions,
validate every provider extension, or redact SDK logs. Optional telemetry failures
remain independent; required-response getter errors and control-flow exceptions
propagate. Mission reports preserve instrumented harms and record fixed errors;
trace wrappers retain completed tool spans. Saved results and scoring formulas
are unchanged: retain producer revisions and recapture comparison evidence after
adopting this boundary. Native response fixtures block sockets and do not claim
live-provider evaluation.

## Generic AgentDojo tool lifetime

**On main after v0.19.0**, every `GenericAgentElement.query` uses a fresh supplied-
tool session. This covers reference LiteLLM, native bridges, and custom agents
when they run through `evaluate_agents` or the generic AgentDojo scan path; it
does not require a tool-call budget or a self-reported tool ledger.

Retained handles stop accepting calls when the task exits, including after an
exception, cancellation, or malformed agent result. A callback still active at
return makes the task incomplete, not a completed binary measurement. An
exception escaping runtime invocation or output defense processing is remembered
even if the agent catches it and supplies a final answer; subsequent supplied
callbacks are denied. Defended tool output must be explicit text, including
intentional empty text. An invalid output raises `AgentResultError` and cannot
be hidden by omitting the returned ledger.

Ordinary lifecycle failures raise `AgentToolExecutionError`, exported from
`dspy_security_bench.agents`. Native adapters share the implementation and retain
their existing `NativeToolExecutionError` specialization and diagnostics. An
exception already escaping the agent/callback keeps its original identity;
the session does not replace control-flow exceptions or store error text.

This is deliberately distinct from **AgentDojo's normal error feedback**:
`FunctionsRuntime.run_function(..., raise_on_error=False)` returns argument-
validation and ordinary domain failures as explicit text. Those observations
remain recoverable, so an agent may correct its arguments and retry. The bridge
does not guess failure from words such as `error` in a string. An exception from
the runtime/defense boundary itself, or a non-text defended observation, instead
means the harness did not complete its callback contract.

Already admitted callbacks may finish and earlier effects remain. The session
does not cancel background work, undo changes, wait forever for callbacks, impose
a time/token budget, or restrict tool access outside the supplied handles. Work
scheduled only after the task exits is denied if it later uses a retained handle;
work already admitted may still finish after the incomplete task has raised.
Owners must join/cancel their background work. The lock protects accounting,
not application data, and does not make a custom agent or runtime thread-safe.
Direct custom `Agent.run`/`CallbackAdapter` calls outside this generic harness do
not acquire this boundary automatically; native bridges retain their own scope.

The existing execution-checked runner aborts an affected scan without publishing
a completed gate or evidence file. Real offline workspace tests cover both
auxiliary and scored phases, while runtime tests cover retained handles,
concurrent task isolation, background calls, and preserved effects. No new score
formula, historical result rewriting, or live provider evaluation is introduced.

## Native supplied-tool failures and lifetime

**On main after v0.19.0**, all five built-in native bridges require their supplied
`BenchTool` callbacks to return explicit text. `None`, booleans, mappings, and
arbitrary objects are not implicitly stringified. Serialize structured results
deliberately in your tool, and use an explicit text success/error response for
expected domain outcomes. An intentional empty string remains valid. The
[OpenAI function-output guidance](https://developers.openai.com/api/docs/guides/function-calling#formatting-results)
likewise recommends an explicit status string for functions without a return value;
this benchmark's text-only contract is narrower than the API's multimodal outputs.

A native SDK's final answer does not erase a failed supplied callback. Each run
has an independent, lock-protected session that records failure categories without
retaining exception messages or tracebacks. After native execution and required
answer admission, an invalid tool return raises `AgentResultError`; a caught
callback exception or unfinished callback raises `NativeToolExecutionError`
(importable from `dspy_security_bench.integrations`). Validation precedes optional
telemetry. Exceptions already escaping the SDK—including cancellation—keep their
existing behavior. Result handling does not replace them with a new exception.

This is deliberately stricter than conversational error recovery. For example,
[LangChain middleware](https://reference.langchain.com/python/langchain/agents/middleware/types/AgentMiddleware/wrap_tool_call)
can catch tool failures and continue. Pydantic AI can turn
[`ModelRetry` into a retry prompt](https://pydantic.dev/docs/ai/tools-toolsets/tools-advanced/#requesting-a-tool-retry).
If those signals come from inside a supplied `BenchTool`, they
still mark this measurement incomplete even if the SDK later returns text.
Schema rejection *before* the callback starts is outside this session, and a
callback that returns explicit domain-error text does not fail merely because
the text contains an error. The check does not inspect model semantics or certify
successful task completion.

New supplied-tool invocations are denied after a callback fails and after the
native run exits. Already admitted concurrent callbacks may still finish; they
are not cancelled or rolled back. Returning with one still active permanently
marks the invocation incomplete, even if it finishes later. Successful tool
records and instrumented harms already observed remain available, but an error
report is not a claim to capture future background effects. A fresh run starts
with fresh state. Client cleanup, pending approvals, and deferred-output admission
keep their existing paths.

This is a **cooperative boundary**, not a sandbox, wall-clock limit, tool budget,
or prevention of access through tools/clients created outside the supplied
callbacks. It does not add JSON Schema enforcement or undo SDK argument coercion.
It does not sanitize SDK logs or original exceptions. Custom callback adapters
retain their own tool-execution semantics; use the explicit tool-budget wrapper
when a task needs an admission limit. Offline fixtures exercise all five real
SDKs, caught errors, concurrency, fresh state, and mission replay without providers.
Preserve producer revisions and recapture comparisons; historical reports are not
rewritten.

## Native SDK telemetry

The stricter native usage extraction is **on main after v0.19.0**. Required
answer/completion checks run before telemetry is exported. Once they pass,
ordinary exceptions from an optional usage accessor no longer invalidate the
completed answer or its tool ledger. An unavailable metadata container/method
yields `{}`; an unreadable
field makes only that quantity unknown. `KeyboardInterrupt`, `SystemExit`, and
async cancellation still propagate. This is not error suppression for model or
tool execution, a retry mechanism, or protection against blocking accessors.

The extraction paths are:

| Bridge | SDK metadata inspected |
|---|---|
| OpenAI Agents | `result.context_wrapper.usage` |
| Pydantic AI | `result.usage()` |
| CrewAI | `result.usage_metrics` |
| AutoGen | Fresh model client's `total_usage()` after client cleanup |
| LangChain | Per-invocation model callbacks reading `AIMessage.usage_metadata` |

Token aliases `prompt_tokens` / `input_tokens` / `request_tokens` and
`completion_tokens` / `output_tokens` / `response_tokens` describe the same two
quantities. All non-null aliases present must be valid and agree; disagreement,
malformed values, or failed alias access omit that quantity instead of choosing
the last field. Missing/null aliases are ignored. Counts, including adapter-level
`requests`, must be nonnegative integers, not booleans or floats. USD cost must
be finite and nonnegative. Other fields, currencies, cache/reasoning details,
and `successful_requests` are not silently converted into these metrics.

The bridge never creates a missing `total_tokens` from input plus output. It
also does not repair arithmetic disagreements between separately exposed counts.
Valid neighboring fields survive; zero is retained only when the SDK exposes
zero. The shared mission normalizer retains supported token/cost fields but
does not export the adapter-only `requests` extension into mission evidence.

**SDK-exposed is not necessarily provider-observed.** SDKs may default missing
values to zero, aggregate partial metadata, or expose computed totals (for
example Pydantic AI's `total_tokens` property). Extraction does not recover those
lost distinctions, prove completeness, reconcile billing, or estimate prices.
Keep producer/framework versions with comparisons; do not treat `{}` as free
execution or compare these estimates as complete cross-framework cost totals.
The [OpenAI usage example](https://developers.openai.com/cookbook/examples/agents_sdk/security_scanners_with_agents_sdk#usage-and-limits)
illustrates reporting response and token counts separately. No live provider
evaluation or historical report rewriting is part of this change.

### Callback coverage and client counter scope

The LangChain bridge supplies a fresh numeric-only callback collector to each
`invoke`. It observes model starts, completions, and errors during execution,
without saving prompts, model output, model names, or exception text. It totals
only token fields that are valid on **every observed completed model call**.
Missing/invalid fields omit that quantity; a failed/pending call, duplicate or
orphan event, or ambiguous lifecycle makes all totals unknown. No callback events
means `{}`, not zero. Only single completed chat generations are supported;
chunks, batched generations, and alternatives are conservatively unknown.

Counts come from callbacks rather than the final message or returned message
history, so pruning history does not discard already observed usage. A closed
snapshot is detached from later callback changes. Synchronization handles
concurrent observed callbacks; it does not add asynchronous benchmark scheduling.
This intentionally uses stricter completeness checks than simply accumulating
the available metadata. LangChain documents its
[callback usage interface](https://docs.langchain.com/oss/python/langchain/models#token-usage).
SDK-free tests exercise missing/invalid metadata, failed and unfinished calls,
duplicates, concurrency, and lifecycle isolation. Native offline graph tests
also exercise recovered errors and pruned returned state.

AutoGen's standard `TaskResult` has no `usage` field. The bridge now reads the
[model client's counters](https://microsoft.github.io/autogen/stable/reference/python/autogen_ext.models.openai.html)
from the fresh client created for that invocation, after closing it and admitting
the terminal answer. Optional counter-access failures stay unknown. Standard
`RequestUsage` exposes prompt and completion counts, so the bridge does not
invent `total_tokens`, request counts, or costs. Custom `TaskResult.usage`
extensions are no longer consulted. A new client on every run prevents lifetime
counts from leaking across cases; native replay tests check this distinction.

Neither approach proves complete provider usage. SDK defaults, silent missing
metadata, hidden retries, unobserved child calls, cache conventions, and work
outside the instrumented invocation may remain invisible. AutoGen reports its
client's aggregate counters, not the callback completeness guarantee used for
LangChain. No prices, currency conversions, resource caps, provider billing
reconciliation, or new report/scoring formulas are introduced.

## Async callbacks in notebooks and services

**On main after v0.19.0**, `CallbackAdapter.arun` awaits a callback in the caller's
event loop. Use it for notebook cells, async request handlers, and clients with
loop-bound connections. It accepts the same text/`AgentResult` contract as `run`,
including results returned by coroutines, general awaitables, futures, and tasks.
For example, this standalone demonstration makes no provider calls:

```python
import asyncio
from dspy_security_bench.integrations import CallbackAdapter

async def run_agent(query, tools, system_directive):
    await asyncio.sleep(0)
    return "Synthetic answer"  # Replace with your trusted application loop.

adapter = CallbackAdapter(run_agent)

async def demo():
    result = await adapter.arun("Inspect a synthetic record", [], system_directive="Use synthetic data")
    assert result.final_answer == "Synthetic answer"

asyncio.run(demo())  # In a notebook with an active loop, use: await demo()
```

In a real evaluation, pass the exact live `BenchTool` instances and trusted
directive supplied by the environment. This convenience API does **not** change
benchmark scheduling: CLI/mission runners and trace/budget wrappers still call
the synchronous `run` contract. It does not make every native framework bridge
async, automatically parallelize trials, or add timeouts. Synchronous callbacks
are invoked inline even by `arun`; a blocking callback still blocks its caller.

For existing synchronous integrations, `run` accepts fresh coroutines and general
awaitables using a temporary loop. When another loop is already running in the
calling thread, it uses a worker and copies the current `ContextVar` bindings.
This preserves request context in the awaited body; changes to worker bindings
do not propagate back. The copy does not clone mutable values or provide tenant
isolation. `run` still blocks until completion. Python's
[runner documentation](https://docs.python.org/3/library/asyncio-runner.html)
explains why the bridge wraps general awaitables for Python versions before
3.14; [context variables](https://docs.python.org/3/library/contextvars.html)
explain the per-thread context boundary.

Pending futures/tasks already belong to a loop: `run` raises `RuntimeError`
directing you to `arun`, without driving their loop or cancelling them. Completed
futures/tasks retain their result, exception, or cancellation. The callback has
already executed when its returned future is checked, so the **owner must still
await or cancel any work it started**. Prefer `await adapter.arun(...)` on that
same owner loop from the beginning. Neither entry point migrates live clients
or pending work across loops; an awaitable capturing a different loop can still
fail under Python's normal [future semantics](https://docs.python.org/3/library/asyncio-future.html).

Both entry points validate completed results identically. Callback exceptions
and cancellation propagate, never become answer text, and do not roll back
earlier effects. Async callers control cancellation/deadlines using their own
application policy; no sandbox, automatic retry, or forced thread cancellation
is provided. Review and trust callback code before invoking either entry point.

## OpenAI Agents result completeness

On main after v0.19.0, the built-in OpenAI Agents bridge accepts only a text
`final_output` with an explicitly empty `interruptions` list. Missing/non-text
answers, absent/malformed interruption state, and pending approvals raise
`AgentResultError`; they are not stringified or substituted with empty text.
An intentional empty text answer is still valid when no interruption is pending.

The [official SDK result guide](https://developers.openai.com/api/docs/guides/agents/results)
distinguishes approval-paused state from a final answer. A pause is valid SDK
behavior but incomplete benchmark execution. This adapter does not approve,
resume, or serialize pending work; use an explicitly reviewed application
workflow outside this one-shot bridge when your evaluation needs human review.
Previously executed effects are not rolled back, and error messages do not copy
SDK state, pending arguments, or output values. The bridge uses the SDK's default
text mode; adapt structured output explicitly through a custom callback.

The optional framework CI job now exercises the actual installed SDK's model
loop with a canned model, real tool invocation, empty output, and an approval
pause. Sockets are blocked and tracing disabled in those fixtures. This is
zero-provider compatibility evidence, not a live model or approval-policy test.

## LangChain final-answer attribution

On main after v0.19.0, the built-in `create_agent` bridge requires a state
dictionary with a nonempty `messages` list ending in an assistant message
(`type == "ai"`). Both `tool_calls` and `invalid_tool_calls` must be explicit
empty lists. User/tool messages, streaming chunks, missing state, and pending
or invalid tool calls raise `AgentResultError`; the bridge never searches back
through history for an older assistant answer or stringifies an arbitrary result.

LangGraph's default `invoke()` exposes dynamic pauses via `__interrupt__`;
nonempty or malformed interruption state is rejected before reading an answer.
An absent marker or an empty list/tuple is allowed, but still requires a complete
terminal assistant message. The bridge does not approve, resume, or persist
paused work. See the [official interrupt guide](https://docs.langchain.com/oss/python/langgraph/interrupts).

Plain text is preserved exactly, including intentional empty text. For list
content, the bridge uses LangChain's normalized `content_blocks`, concatenating
only explicit text blocks without inserting separators. Reasoning, multimodal,
and other non-text metadata are not stringified into the score. A list with no
text, malformed blocks/text, or unfinished client-tool blocks is an error.
This follows the distinction between text and other
[standard message content](https://www.langchain.com/blog/standard-message-content),
not a claim that non-text outputs were evaluated or traces authenticated.

Custom graph envelopes, serialized message dictionaries, structured responses,
and multimodal evaluation need an explicit custom callback. Test doubles for
this bridge must expose the same required message and tool-state fields. Real
SDK CI fixtures cover tool execution, empty/text-block answers, dynamic approval,
and static pre-tool pauses using a canned model, blocked sockets, and disabled
tracing; no provider or external approval service is used.

## Pydantic AI text output and deferred work

On main after v0.19.0, the built-in Pydantic AI bridge accepts only an explicit
string `AgentRunResult.output`. Missing output, `None`, containers, structured
models, and deferred request objects raise `AgentResultError`; they are not
stringified into answers. Required output is checked before optional usage is
read. Text is preserved exactly, including an intentionally empty result value.
That does not override the SDK's own retries/errors for empty model responses.

The SDK's [deferred-tools contract](https://pydantic.dev/docs/ai/tools-toolsets/deferred-tools/)
allows runs configured for deferred work to return `DeferredToolRequests` instead
of text. Such output may require approval or external execution; it is not a
completed answer for this one-shot bridge. Native tests include an approval
request alongside stale text and verify that it is neither scored nor approved.
The adapter does not add approval policies, resolve external calls, resume runs,
or serialize deferred state. Earlier completed tool effects are not undone.

The adapter keeps the SDK's default text mode and synchronous `run_sync` entry
point. For structured scoring, approval workflows, or async clients, implement
an explicitly reviewed [custom callback](#custom-and-mcp-backed-loops) that owns
completion and serialization. Do not convert an unresolved request to an empty
answer merely to satisfy this contract. Existing saved evidence is not rewritten;
retain producer revisions and recapture runs when adopting the new boundary.

Native CI uses the real Pydantic agent graph and
[`FunctionModel`](https://pydantic.dev/docs/ai/guides/testing/) with model requests
disabled, sockets blocked, and instrumentation disabled. It covers parameterized
tools, default arguments, fresh per-run state, usage, deferred approvals/calls,
structured output, and empty-response errors. SDK-free tests additionally cover
missing fields, intentional empty results, and objects that must never be
represented. These are offline compatibility checks, not provider evaluations.

## AutoGen execution and final-answer attribution

On main after v0.19.0, the default AutoGen name is **`autogen_agent`**, replacing
`autogen-agent`, which the native SDK rejected before execution. Explicit names
must be Python identifiers; this bridge also reserves `user` for the input
message source. `max_tool_iterations` must be a positive integer, not a boolean.
These checks run at construction and again before creating a native client, so
invalid mutated configuration also fails early. The underlying
[AutoGen base-agent implementation](https://microsoft.github.io/autogen/stable/_modules/autogen_agentchat/agents/_base_chat_agent.html)
documents the identifier requirement. Normal doctor does not execute the native
agent and therefore cannot substitute for an execution test.

The shared generated tool wrapper now supplies both `inspect.signature` and
`typing.get_type_hints` metadata. SDKs that read annotations independently can
construct tools with required and defaulted arguments; previously AutoGen raised
`KeyError` for parameterized tools. This preserves the existing primitive type
mapping, not complete validation or conversion of arbitrary JSON Schemas.

For the built-in single-agent bridge, the native result must expose:

- explicit `stop_reason=None`, not team termination or missing stop state;
- a nonempty message list or tuple;
- a terminal message whose `source` equals the configured agent name; and
- a `TextMessage` or `ToolCallSummaryMessage` with explicit string `content`.

Intentional empty text is valid. Handoffs, stop messages, thoughts, tool events,
streaming chunks, structured/multimodal objects, stale earlier messages, and
arbitrary result representations are not final answers. Unsupported state raises
`AgentResultError` after client cleanup. Prior tool effects are not rolled back;
no handoff is automatically followed or approved. Serialized dictionaries and
team/custom completion rules require a reviewed `CallbackAdapter`.

AutoGen can legitimately return a tool summary after reaching its configured
iteration limit, so that supported terminal text remains accepted. It is not
necessarily a new model-generated answer or proof of successful work. The
[official AssistantAgent behavior](https://microsoft.github.io/autogen/stable/reference/python/autogen_agentchat.agents.html)
distinguishes text, tool summaries, and handoffs. The unchanged default is ten
tool iterations. This SDK iteration setting is **not** the benchmark's hard
[tool-call budget](tool-call-budgets.md), a timeout, or a resource bound.

Native CI tests use the real agent loop with AutoGen's
[replay model client](https://microsoft.github.io/autogen/stable/reference/python/autogen_ext.models.replay.html),
blocked sockets, and no provider credentials. They exercise required/defaulted
arguments, fresh run state, normal/empty answers, tool-limit summaries, handoffs,
and exception cleanup. This is deterministic compatibility evidence, not a live
provider evaluation. Saved reports are not rewritten; retain producer revisions
and recapture evidence when comparing changes to native execution behavior.

## CrewAI native answers and active event loops

These corrections are **on main after v0.19.0**. The built-in bridge uses
CrewAI's standalone `Agent.kickoff`, with delegation disabled, rather than a
multi-agent Crew/Flow workflow. Its returned `agent_role` must be a string
matching the configured adapter name, and `raw` must be a string. Missing
fields, mismatched roles, dictionaries, arrays, and other objects raise
`AgentResultError` before optional usage is read; they are never coerced into
scored answers. Prior tool effects are not rolled back.

Intentional empty text remains valid at the adapter boundary. The native SDK
may reject an empty model response before producing an output. The adapter
evaluates the SDK's exposed `raw` text, including JSON already serialized by
the SDK; it does not interpret a `pydantic` object as an answer or validate that
object's schema. Role metadata is not authentication, and a text result is not
proof of successful work, approved actions, or complete execution evidence.
Custom team/approval/resumption behavior needs a reviewed `CallbackAdapter`.

In the locked CrewAI SDK, `kickoff()` returns a coroutine when it detects an
active event loop. The bridge now consumes that awaitable before reading the
result. Its synchronous `run()` still **blocks**: inside an existing loop the
coroutine runs in a worker with copied `ContextVar` bindings. This is not an
async benchmark scheduler or support for resources bound to the caller's loop.
Use [an async callback](#async-callbacks-in-notebooks-and-services) for integrations
that need to await work on their own event loop. No timeout, cancellation policy,
automatic approval, or resource sandbox is added.

The optional-framework CI matrix runs the actual SDK executor with a canned
[custom BaseLLM](https://docs.crewai.com/en/learn/custom-llm), blocked Python
sockets, and temporary SDK storage. It covers native function calling and ReAct
tool dispatch, required/defaulted arguments, repeated fresh agents, per-run
usage, request context, empty-response errors, and model failure after tool
effects, both inside and outside an event loop. CrewAI's strict provider schema
can mark defaulted arguments required; the fixture also tests local dispatch
when such an argument is omitted. This does not establish provider conformance
or full JSON Schema fidelity.

Fixtures disable telemetry, tracing, and version checks before importing CrewAI.
The adapter does **not** change an application's global observability settings;
review the SDK's [telemetry controls](https://docs.crewai.com/en/telemetry) for
your deployment. These deterministic checks make no live provider requests and
do not measure provider quality. Historical reports stay unchanged; retain
producer revisions and recapture evidence when comparing behavior changes.

## What doctor checks

The strengthened checks and `--manifest-only` mode are **on main after v0.19.0**;
install a reviewed source revision to use them. Doctor does not directly call
models or `agent.run()`. **Normal mode imports target code and calls its factory
twice.** Those imports, constructors, and Python import hooks can perform any
side effects their authors implement, including network requests or model spend.
Use normal mode only for trusted, reviewed code in an appropriate environment.
It checks:

1. the integration manifest and framework declaration;
2. the optional framework import and installation hint;
3. that the factory returns two distinct instances, each with a non-blank string
   name and callable run method, without invoking those methods;
4. parsed workflow settings: exactly one recognized ProofRun reusable-workflow
   job, its matching factory/engine reference, and its effective declared
   attestation permissions (job-level permissions replace workflow defaults); and
5. whether expected provider credentials exist locally, reported as warnings
   rather than exposing their values.

Use `dspy-security-bench doctor --json` in other developer tooling. A missing
local credential is a warning because the secret may exist only in GitHub.

### Inspect before executing target code

```bash
dspy-security-bench doctor --root . --manifest-only --json
```

This mode reads only the integration manifest and optional generated workflow.
It does not inspect target imports, call factories, search dependency manifests,
invoke Python import hooks for framework discovery, or look up credentials.
It can therefore inspect the declarations before optional SDKs are installed.
It does not prove those declarations are true or the target can run.

JSON retains `passed` and `checks`, and adds `mode`, `target_import_attempted`,
and `factory_calls_attempted`. Skipped runtime/credential checks have status
`not_checked`, not `pass`. Exit 0 means the selected checks have no failure;
exit 1 means a check failed. A manifest-only pass is not runtime readiness.
Invalid manifests or failed static workflow/import checks prevent target loading
in normal mode too. A missing optional workflow is a warning, not a claim that
one exists. These reports are diagnostics, not attestations or deployment approval.

Manifests use the exact nine fields generated by `integrate` and typed schema
version 1. Duplicate JSON keys, malformed field types, mismatched framework import
names, control characters, and unsupported engine references are rejected.
Manifest and workflow reads accept regular, non-linked files up to 1 MB, reject
observed links/reparse points below the selected root, and require stable
owner-controlled paths. Workflow YAML uses a restricted bounded subset: duplicate
keys, collection aliases, merges, unsupported tags, excessive nesting, and
oversized numeric literals fail. This is not a complete GitHub workflow validator;
expressions, other jobs, organizational policies, and hosted execution remain
outside the local check. Comments do not confer permissions or supply input values.

Static and factory-error diagnostics omit raw exception text. Ordinary Python
stdout/stderr writes during factory import/construction are discarded without
buffering, preserving machine-readable output. This is not an OS sandbox:
native writes, pre-existing logging handlers, malicious code, and concurrent file
changes are not isolated; there is no runtime CPU/network limit or secret scanner.

GitHub documents [job-level permission behavior](https://docs.github.com/en/actions/reference/workflows-and-actions/reusing-workflow-configurations).
Python documents that [finding a dotted module spec imports its parent](https://docs.python.org/3/library/importlib.html#importlib.util.find_spec);
the manifest cannot select arbitrary import probes, and manifest-only mode skips
those probes entirely.

## Framework documentation

- [OpenAI Agents SDK quickstart](https://developers.openai.com/api/docs/guides/agents/quickstart)
- [LangChain agents](https://docs.langchain.com/oss/python/langchain/agents)
- [Pydantic AI function tools](https://pydantic.dev/docs/ai/tools-toolsets/tools/)
- [CrewAI direct agent interaction](https://docs.crewai.com/en/concepts/agents)
- [AutoGen AgentChat agents](https://microsoft.github.io/autogen/stable/user-guide/agentchat-user-guide/tutorial/agents.html)

These integrations reduce wiring effort; they do not make five frozen synthetic
scenarios representative of deployment, independently authenticate a remote
provider response, or turn ProofRun into a safety or compliance certificate.
