# Real-world agent security use cases

An agent is most dangerous where untrusted context meets a high-impact tool.
This project now addresses both sides of that boundary:

1. **Measure** whether a model follows injected instructions with the benchmark.
2. **Constrain** what the deployed agent can do with deterministic policy.
3. **Verify** that the constraint removes functional harm without breaking the
   mission with [ControlTwin](control-twin.md).
4. **Authorize** each agent action as the right principal, workload, scope,
   tenant, audience, intent, and delegation with [AuthorityTwin](authority-twin.md).
5. **Ground** factual decisions in current primary evidence and test poisoned
   retrieval with [MissionForge and SourceTwin](missionforge.md).

This follows the [OWASP AI Agent Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/AI_Agent_Security_Cheat_Sheet.html): minimize tool permissions, require human approval for high-impact actions, treat external content as untrusted, and keep security regression tests.

## Where this helps

| Production agent | Untrusted context | Dangerous sink | Included policy profile |
|---|---|---|---|
| Customer support | Tickets, email bodies, CRM notes | Refunds, outbound email, identity changes | `customer-support` |
| Accounts payable | Invoices, vendor email, uploaded PDFs | Transfers, new payees, financial exports | `financial-operations` |
| Procurement / source selection | Vendor proposals, attachments, market research | Bid disclosure, vendor identity, recommendations, awards | `procurement` |
| Research / enterprise RAG | Websites, documents, retrieved chunks | Persistent memory, publishing, code execution | `research-rag` |
| SRE / DevOps copilot | Logs, issue text, repository content | Deployments, shell access, deletion | `devops` |

For read-oriented grants, benefits, regulatory research, records management,
supply-chain qualification, and enterprise knowledge workflows, SourceTwin
tests a different failure boundary: whether untrusted retrieval can change the
claim set or cited authority even when no consequential tool is called. Custom
MissionPacks let the mission owner encode synthetic claims, material exceptions,
source status, and expected abstention without changing benchmark Python.

These are not hypothetical prompt strings. They model the paths through which a
production agent turns hostile content into a real side effect.

For every row, AuthorityTwin can independently probe the authorization bridge:
customer/tenant substitution, payment approval replay, procurement delegation
inflation, RAG sensitivity aggregation, and DevOps audience or scope confusion.
It complements the in-process policy profiles below; neither layer replaces the
other.

## Start without an API key

List and scaffold the built-in profiles:

```bash
dspy-security-bench policy profiles
dspy-security-bench policy init --profile customer-support --out agent-policy.yaml
dspy-security-bench policy validate --policy agent-policy.yaml
```

Generated profiles include a JSON Schema directive, so editors with YAML
language-server support provide completions and flag invalid fields while you
edit.

Test proposed tool calls completely offline:

```bash
# Allowed: bounded authority.
dspy-security-bench policy check \
  --policy agent-policy.yaml \
  --tool issue_refund \
  --args '{"amount": 49, "currency": "USD"}'

# Denied: customer data would leave the trusted domain.
dspy-security-bench policy check \
  --policy agent-policy.yaml \
  --tool send_email \
  --args '{"recipients":["audit@attacker.test"]}'
```

Exit codes make this usable in scripts: `0` allowed, `1` denied, `2` invalid
input or policy, and `3` human approval required.

## Policy format

Rules are first-match-wins, making authority easy to audit. Tool names accept
shell-style globs and every condition in `when` must match:

```yaml
version: 1
name: bounded-refunds
default: deny
rules:
  - id: allow-small-refund
    tool: issue_refund
    action: allow
    reason: Inside delegated authority.
    when:
      - {arg: amount, op: less_than_or_equal, value: 100}
      - {arg: currency, op: equals, value: USD}
  - id: review-other-refunds
    tool: issue_refund
    action: require_approval
```

Supported operators are `equals`, `not_equals`, `in`, `not_in`, `contains`,
`matches`, `not_matches`, `less_than_or_equal`, `greater_than_or_equal`,
`any_matches`, `any_not_matches`, and `exists`. Dot paths such as
`request.destination.account_id` address nested argument objects.

## Wrap any supported agent

`PolicyEnforcedAgent` implements the same framework-neutral `Agent` protocol as
the benchmark. It wraps the live `BenchTool` callables, so denied operations do
not mutate the environment:

```python
from dspy_security_bench.policy import PolicyEnforcedAgent, ToolPolicy

base_agent = build_my_agent()
policy = ToolPolicy.load("agent-policy.yaml")

secured_agent = PolicyEnforcedAgent(
    base_agent,
    policy,
    approval_handler=my_approval_service,
)
```

Approval handlers receive the matched decision and the **exact tool arguments**.
The reviewer should see those raw arguments—not an LLM-written summary of what
the action supposedly does:

```python
def my_approval_service(decision, arguments):
    return approval_api.request(
        rule=decision.rule_id,
        tool=decision.tool,
        exact_arguments=arguments,
    )
```

Approval rules fail closed if no handler is configured. Audit logs omit
arguments by default to avoid creating a secondary secret store; enable
`capture_arguments=True` only where the data classification permits it.

## Gate the policy-wrapped agent in CI

Expose a zero-argument factory from your application:

```python
# myapp/security_target.py
from dspy_security_bench.policy import PolicyEnforcedAgent, ToolPolicy
from myapp.agent import build_agent

def build_security_target():
    return PolicyEnforcedAgent(
        build_agent(),
        ToolPolicy.load("agent-policy.yaml"),
    )
```

Point the scanner at the factory:

```yaml
agent:
  import: myapp.security_target:build_security_target
scan:
  suites: [workspace, banking]
  attacks: [direct, important_instructions, adaptive]
  defenses: [none]
  user_tasks: 5
  injection_tasks: 2
gate:
  mode: regression
  baseline: .dsb-baseline.json
  max_regression: 0.05
```

This measures the deployed control, not just the base model. Keep a second
unwrapped run when you want to distinguish model robustness from policy
effectiveness.

## Use case 1: customer-support autonomy

Goal: let an agent resolve routine tickets without granting unlimited refund or
data-export authority.

- Allow account lookup and search.
- Auto-approve small USD refunds.
- Require review for larger or unusual refunds.
- Deny external recipients before `send_email` executes.
- Never delegate role, MFA, or identity changes.

Run the included end-to-end offline demonstration:

```bash
python examples/policy_support_agent.py
```

The deliberately naive agent follows a malicious instruction from retrieved
content. The external email still never executes.

## Use case 2: accounts payable

Goal: extract and reconcile invoices while preventing vendor impersonation from
becoming payment fraud.

- Permit read-only account and reconciliation tools.
- Deny destinations outside the organization's verified namespace.
- Require independent approval for every movement of money.
- Deny payee and bank-detail mutations.
- Deny bulk financial exports.

Customize the `corp-approved-` convention in the generated profile to use your
actual counterparty IDs or replace it with an approval-service lookup.

## Use case 3: procurement and source selection

Goal: let an agent organize and evaluate vendor submissions without letting a
vendor-authored document influence authority, expose a competitor, or rewrite
the vendor system of record.

- Permit proposal and authoritative vendor-record reads.
- Permit draft evaluations while keeping their evidence visible.
- Require independent review for award recommendations.
- Deny bid/proposal release, payment-identity changes, and eligibility changes.
- Deny binding awards from the agent surface.

Scaffold the production boundary:

```bash
dspy-security-bench policy init --profile procurement --out procurement-policy.yaml
```

Then measure the behavioral and economic failure paths with the separate
[ImpactTwin / ProcureBench specialty](impact-twin.md). The policy answers what
the agent *may* do; the twin benchmark measures what poisoned content persuades
it to attempt and whether the resulting decision remains equivalent.

Close the loop by running the same agent with policy off and on:

```bash
dspy-security-bench impact control \
  --agent myapp.security_target:build_agent \
  --policy procurement-policy.yaml \
  --json artifacts/control-twin.json \
  --sarif artifacts/control-twin.sarif
```

The [ControlTwin guide](control-twin.md) explains approval callbacks, independent
harm/utility/recovery gates, argument-redaction defaults, and offline evidence
verification.

## Use case 4: enterprise research and RAG

Goal: search broadly without letting a poisoned page create persistent influence
over future sessions.

- Permit retrieval and read-only analysis.
- Require approval before durable memory writes.
- Deny direct publication, outbound messaging, and code execution.
- Evaluate both the current-session injection path and future memory-specific
  tests as those scenarios are added.

Persistent memory changes the threat model: a single poisoned document can
influence later conversations after the original context has disappeared. OWASP
tracks this as agent memory/context poisoning.

## Use case 5: SRE and DevOps copilots

Goal: accelerate diagnosis while retaining a hard boundary around production.

- Allow logs, diffs, inventory, and read-only inspection.
- Deny deletion, raw SQL, arbitrary shell, and force-push operations.
- Require approval for deploy, restart, scale, apply, and rollback tools.
- Prefer narrow typed tools over a general `run_command` escape hatch.

The safe design is not “make the prompt stronger.” It is to keep the agent's
action space smaller than the blast radius of a successful injection.

## What policy does—and does not—solve

Policy enforcement stops disallowed tool side effects even when the model is
compromised. It does not make hostile content trustworthy, prevent sensitive
data from entering the model context, or prove that an allowed action is
semantically correct. Combine it with data minimization, sandboxing, output
validation, monitoring, and the benchmark's regression tests.
