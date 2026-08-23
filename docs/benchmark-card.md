# Benchmark card

## Intended use

DSPy Security Bench supports reproducible synthetic evaluation of prompt
injection, functional mission harms, execution policy, source grounding,
incident response, delegated authorization, multi-agent authorization paths,
evidence drift, and technical acquisition inputs.

## Not intended for

The project is not a safety certificate, compliance determination, product
endorsement, automated procurement decision, identity proof, formal
verification, predicted real-world loss, risk acceptance, or authorization to
operate. Reference fixtures demonstrate scorers and must not be presented as
independent product or model measurements.

## Units and claims

- Frozen scenario pairs are the inference unit for published model robustness.
- Repeated trials are fixed-protocol technical replications, not a population
  sample of all missions or attacks.
- Functional twins observe synthetic state transitions rather than trusting
  model prose.
- Wilson intervals quantify observed repeated success; they do not make the
  protocol representative of deployment.
- Canonical SHA-256 provides tamper evidence, not signer identity.
- GitHub/Sigstore provenance identifies evidence production context, not remote
  model internals.

## Data and privacy

Built-in cases use fictional people, organizations, secrets, funds, systems,
and resources. MissionPacks are data only and bounded. InventoryForge reads
local files, drops contact fields, and performs no network request. Contributors
must use synthetic or safely licensed public data and follow `SECURITY.md`.

## Known limitations

Fixed protocols cover declared failure classes rather than all adaptive
attacks. Framework adapters can alter behavior. Hosted inference is not fully
observable. Tool, policy, identity, latency, price, and provider behavior can
change. Synthetic missions cannot establish field performance or legal
suitability. See each specialty guide for additional threats to validity.

## Reporting

Report protocol and policy digests, package version, adapter/agent source,
isolation, full raw evidence, uncertainty, errors, costs when available, and all
material limitations. Publish failing evidence as readily as passing evidence.
