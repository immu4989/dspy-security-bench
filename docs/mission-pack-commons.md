# Signed MissionPack Commons

The signed MissionPack workflow lets a community distribute data-only mission
protocols with a self-contained Ed25519 signature envelope and a verifiable
local catalog. A signature establishes integrity and possession of a private
key; it does not establish that the signer is trusted or that the pack is safe,
correct, authoritative, approved, or government-authored.

Install the optional signing dependency:

```bash
pip install "dspy-security-bench[signing]"
```

## Create and sign a pack

```bash
dspy-security-bench pack keygen \
  --private-key mission-pack-private.pem \
  --public-key mission-pack-public.pem
dspy-security-bench pack sign my-mission-pack.yaml \
  --private-key mission-pack-private.pem \
  --signer "owner-defined identity" \
  --out my-mission-pack.signed.json
dspy-security-bench pack verify-signature my-mission-pack.signed.json
```

The private key is created with mode `0600`. Protect it using the organization's
normal key-management controls and never commit it. The envelope embeds the
validated data-only pack, public key, signature, signer label, protocol digest,
and its own canonical digest, so offline verification needs no key server.

## Build a local catalog

```bash
dspy-security-bench pack catalog-build ./*.signed.json \
  --out mission-pack-catalog.json
dspy-security-bench pack catalog-verify mission-pack-catalog.json
```

Catalog verification rechecks each referenced envelope, signature, protocol
digest, and catalog digest. Use repository review, protected branches, named
maintainers, reproducible tests, and an explicit trust policy to decide which
signing keys and pack content are acceptable.

## Built-in public-service examples

```bash
dspy-security-bench pack list
dspy-security-bench pack describe benefits-assistance
dspy-security-bench pack describe grants-review
dspy-security-bench pack describe emergency-logistics
dspy-security-bench pack describe records-release
dspy-security-bench pack describe critical-infrastructure
```

These five one-pair packs model benefits review boundaries, grant conflicts,
emergency dispatch authority, records-release controls, and critical-
infrastructure operator confirmation. They are fictional, maintainer-authored
examples—not agency requirements, operational procedures, endorsements, or
deployable policy. Accountable subject-matter owners must replace assumptions,
expand coverage, validate accessibility and privacy, and approve expected
outcomes before organizational use.

MissionPacks remain declarative YAML/JSON. Pack data is validated and never
executed as Python. Signatures do not make hostile content benign, so review
every signed pack as untrusted input before running it against an agent.
