# Security policy

## Supported versions

Security fixes are provided for the latest release. Older releases should be
upgraded before a report is reproduced.

| Version | Supported |
|---|---|
| Latest PyPI and GitHub release | Yes |
| Older releases | No |

## Report a vulnerability privately

Use GitHub's **Report a vulnerability** form under the repository Security tab:

<https://github.com/immu4989/dspy-security-bench/security/advisories/new>

Include the affected version or commit, impact, minimal reproduction, and any
suggested mitigation. Do not include API keys, personal data, production system
details, or third-party secrets. You should receive an acknowledgement within
five business days. The maintainer will coordinate validation, remediation,
release, and disclosure with the reporter.

## Scope

In scope are vulnerabilities in the package, CLI, GitHub Action, evidence
verification, policy enforcement, release pipeline, and hosted dashboard. A
model following a benchmark injection is a research result, not by itself a
vulnerability in this project. Reports about systems you are not authorized to
test, exposed credentials, or live government/company infrastructure are not
accepted; notify the affected organization through its approved channel.

The benchmark and FederalProof exports do not provide a certification,
authorization to operate, legal determination, or operational incident-response
guidance.

## TraceProof data handling

TraceProof processes OTLP JSON offline and uses a deny-by-default allowlist, but
operators remain responsible for the source telemetry and output artifacts.
Do not import credentials, CUI, classified information, personal data, customer
content, or production traces unless you are authorized and the local retention
boundary permits it. Pseudonymized identifiers remain linkable and may be
guessable when the source space has low entropy.

Review the generated redaction policy before use, keep input and output files in
approved storage, and inspect the redaction counters. If sensitive content is
found in a TraceProof artifact, stop distribution, follow the owning
organization's incident process, rotate exposed credentials where applicable,
and report a sanitizer defect privately when the package failed its documented
contract. Do not attach sensitive artifacts to a public issue.

The Runtime Kit intentionally omits queries, directives, arguments, results,
and credentials at collection time. It also rejects arbitrary application
attributes outside the bounded project security namespace. This reduces
exposure but does not prove that upstream instrumentation, custom policy code,
Collector processors, or operator-selected files contain no sensitive data.
Run `dspy-security-bench trace challenge`, inspect the sanitized evidence, and
submit only the generated community bundle—not raw OTLP—to public registries.
