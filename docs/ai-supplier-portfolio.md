# Offline AI supplier portfolio review

Use this workflow when an acquisition team, security reviewer, or platform owner
has several suppliers' AI bills of materials and wants to apply the same
disclosure requirements consistently. It reduces repeated manual intake work;
it does not decide which supplier is safer or should win a contract.

## Run the fictional example

```bash
dspy-security-bench bom intake-ai-portfolio \
  --manifest examples/ai-supplier-portfolio.json \
  --policy examples/ai-bom-disclosure-policy.json \
  --source-root examples \
  --out-dir artifacts/supplier-portfolio

dspy-security-bench bom verify-ai-portfolio artifacts/supplier-portfolio \
  --manifest examples/ai-supplier-portfolio.json \
  --policy examples/ai-bom-disclosure-policy.json \
  --source-root examples
```

Open `artifacts/supplier-portfolio/review.md`. It links to each supplier's
six-file intake pack. `portfolio.json` records the shared policy digest, each
result, input-manifest digest, summary counts, and per-file hashes. Verification
rebuilds every file rather than merely trusting those hashes.

The example uses the same fictional source pair twice under two distinct
owner-assigned labels. It demonstrates the batch mechanism, not an assessment
of two real vendors. Each pair yields four expected disclosure findings.

## Prepare real submissions

Retain the owner's approved policy independently. Do not let a supplier silently
replace it; use `bom compare-ai-policy --fail-on-relaxation` when reviewing policy
updates. Assign each submission a unique lowercase slug, preferably a
pseudonymous case ID when supplier names are sensitive.

```json
{
  "schema_version": 1,
  "manifest_type": "dspy-security-bench-ai-supplier-portfolio",
  "suppliers": [
    {
      "supplier_id": "case-001",
      "cyclonedx_source": "case-001/cyclonedx.json",
      "spdx_source": "case-001/spdx.json"
    }
  ]
}
```

Paths are relative POSIX paths beneath the explicit `--source-root`. Absolute
paths, dot segments, duplicate IDs, and unknown manifest fields are rejected.
Resolved source paths cannot escape that root, including through symbolic links.
Only regular local files are read. No URLs are fetched and no remote contexts
are resolved. Use a private, stable input directory: this is not a filesystem
sandbox against a local process concurrently replacing files.

The current workflow requires **both** a supported CycloneDX 1.7 ML-BOM and SPDX
3.0.1 AI/Dataset source for each submission. It does not infer that components
across those documents describe the same model. Limits are 25 suppliers,
2 MB per source, and 100 MB of generated per-supplier artifacts. A malformed
common manifest or policy aborts before output creation. An invalid individual
submission is recorded while other submissions continue.

## Interpret results and CI exits

| Result | Meaning | Finding count |
| --- | --- | --- |
| `requirements_met` | Supplied structural evidence satisfies the configured requirements | 0 |
| `owner_review_required` | One or more configured disclosure requirements are missing | Positive |
| `input_invalid` | Input unavailable, invalid JSON, unsupported, or rejected by the bounded importer | `null`, not zero |

`complete` means every submission was evaluated, not that every requirement
was met. Counts are not comparable security scores. In particular, the total
finding count excludes invalid submissions; always inspect `input_invalid`.

Creation returns exit code 2 if any submission is invalid, after preserving the
partial review. With `--fail-on-findings`, a fully evaluated portfolio containing
findings returns 1. Otherwise creation returns 0. Errors validating a common
policy/manifest or writing output also return 2; such failures need not produce
a pack. Output must be a fresh directory; there is no overwrite flag. An I/O
failure may leave a partial directory, which verification rejects.

Verification returns 0 only for exact reproducibility, including reproducible
partial-intake outcomes. It is **not** the policy gate. It rejects altered
reviews, missing/extra files or directories, and symbolic links in the output.
For evaluated suppliers, original source content is bound by the nested intake
manifests. For invalid submissions, a reproduced error state does not establish
the identity of unreadable or unsupported source bytes.

## Sharing and claim boundaries

The pack does not copy original BOM documents, raw source paths, or source-error
details. It does include the owner-assigned supplier labels, policy owner label,
hashes, structural metadata, and field-presence evidence; review these before
sharing. Hashes do not provide confidentiality for guessable inputs. Keep the
manifest, policy, and original source documents separately for reproduction.

Authentication of suppliers, truth and adequacy of disclosures, model behavior,
license rights, legal compliance, procurement selection, and deployment approval
remain separate work. This tool performs none of them automatically.

Schemas: [input manifest](../dspy_security_bench/schemas/agentbom-ai-portfolio-manifest.schema.json)
and [portfolio report](../dspy_security_bench/schemas/agentbom-ai-portfolio-report.schema.json).
Runtime validation additionally enforces unique supplier IDs, path containment,
and exact source-bound reproduction; schema validation alone does not.
