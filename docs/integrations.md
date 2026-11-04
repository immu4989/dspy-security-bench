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
reported. These are provider-reported estimates, not billing reconciliation;
unreported SDK retries, tool execution costs, and provider-side work are not
included. Custom agents own the completeness of usage they supply.

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
