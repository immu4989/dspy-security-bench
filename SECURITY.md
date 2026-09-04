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

## AssuranceLedger data handling

Full AssuranceLedger, Gossip, ReReview, and conformance inputs can contain
reviewer identifiers, declared organizations, review-envelope digests, key
lifecycle events, and complete embedded source reports. Treat them according to
the sensitivity of the underlying review process. Do not place classified
information, CUI, personal data, credentials, private incident details, or
production log contents into the public demo, an issue, a pull request, or a
public evidence registry.

ForkProof and ConsistencyProof deliberately omit log and review entries, but
retain public keys, signed checkpoints, log origin, policy identifiers, and
source digests. ObserverReceipt hashes the channel locator but retains observer
and declared organization identifiers. WitnessConflict retains the witness keys
and organizations attributed to both views. These are minimized artifacts, not
anonymous artifacts; review them before distribution.

CapabilityManifest and IntegrationLock expose schema/protocol identities and
digests rather than review content. Their integrity hashes are not signatures.
Protect an owner-approved lock through the organization's existing signed
release, configuration-management, or artifact-governance controls. The tools
never notify, revoke, roll back, deploy, authorize, or accept risk automatically.

AssuranceTrustRoot artifacts intentionally disclose public keys, algorithm
identifiers, declared entity and organization labels, role thresholds, exact
authorized policy digests, version history, expiration, and signatures. They do
not contain private keys, but that metadata can still reveal governance
relationships. Review it before external distribution. Keep every signing key
in organization-approved custody; pass only local key paths to
`create-trust-root`, never key contents. A `trusted_*` result proves continuity
from the caller-selected anchor, not that key storage, identity proofing,
organizational independence, algorithms, or policies meet a deployment's
security or compliance requirements.

AssuranceTrustRootChain reports embed every supplied public root so another
party can recompute each hop offline. That history may expose past governance
relationships even when keys are retired. Distribute it according to the same
metadata review boundary. Expired intermediate roots are historical evidence,
not current authority; only a current final root can produce `trusted_chain`.
The verifier does not fetch missing roots or know whether a newer root was
withheld, so persist a separately governed minimum version where freshness is
security-relevant.

TrustRecoveryDrill intentionally accepts only simulation records and embeds
actor/organization labels, event times, evidence classes, and evidence digests.
Those fields can reveal incident-response structure and drill cadence. Review
them before sharing, keep the underlying records out of public artifacts, and
do not hash low-entropy secrets as evidence identifiers. A passing drill does
not authorize key recovery or prove a real response will work; the analyzer
activates no replacement root and performs no notification or remediation.
