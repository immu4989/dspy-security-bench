#!/usr/bin/env node

/**
 * Independent, zero-dependency Node.js runner for the immutable
 * AssuranceLedger RootViewQuorum v1 known-answer pack.
 *
 * This deliberately does not import or execute the Python reference verifier.
 */

import { createHash, createPublicKey, verify as verifySignature } from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const VECTOR_VERSION = "assuranceledger-root-view-vectors-v1";
const ROOT_VIEW_VERSION = "assuranceledger-root-view-quorum-v1";
const ROOT_VERSION = "assuranceledger-trust-root-v1";
const EXPECTED_MANIFEST_SHA256 =
  "e39be2384f1ff8e49d8e62e26df112a01d181e5ece06a9e9f7df36dd93750e08";
const EXPECTED_CASE_IDS = [
  "matching-quorum",
  "lagging-view-preserved",
  "same-version-conflict",
  "newer-root-reported",
  "duplicate-observer",
  "nonce-mismatch",
  "invalid-observer-signature",
  "rehashed-summary-tamper",
];
const MANIFEST = "vector-manifest.json";
const MAX_FILE_BYTES = 5_000_000;
const DIGEST = /^[0-9a-f]{64}$/;
const IDENTIFIER = /^[a-z0-9]+(?:-[a-z0-9]+)*$/;
const NONCE = /^[A-Za-z0-9._:-]{16,200}$/;
const SAFE_PATH = /^(?:[a-z0-9-]+\/)*[a-z0-9-]+\.json$/;

invariantNodeVersion();

const POLICY_FIELDS = new Set([
  "schema_version",
  "policy_type",
  "protocol_version",
  "quorum_id",
  "trust_domain",
  "observers",
  "minimum_observers",
  "minimum_distinct_organizations",
  "claim_boundary",
  "policy_sha256",
]);
const OBSERVER_FIELDS = new Set([
  "entity_id",
  "organization_id",
  "public_key_sha256",
  "public_key_spki_base64",
]);
const RECEIPT_FIELDS = new Set(["statement", "observed_root", "observer_signature"]);
const STATEMENT_FIELDS = new Set([
  "protocol_version",
  "root_view_policy_sha256",
  "trust_domain",
  "candidate_root_sha256",
  "request_nonce",
  "observer_id",
  "observer_organization_id",
  "observer_key_sha256",
  "observed_root_sha256",
  "observed_root_version",
]);
const OBSERVER_SIGNATURE_FIELDS = new Set(["keyid", "signer_id", "signature_base64"]);
const ROOT_FIELDS = new Set([
  "schema_version",
  "root_type",
  "protocol_version",
  "trust_domain",
  "version",
  "issued_at",
  "expires_at",
  "previous_root_sha256",
  "keys",
  "roles",
  "authorized_policies",
  "signatures",
  "previous_root_signatures",
  "root_sha256",
]);
const ROOT_SIGNED_FIELDS = [
  "schema_version",
  "root_type",
  "protocol_version",
  "trust_domain",
  "version",
  "issued_at",
  "expires_at",
  "previous_root_sha256",
  "keys",
  "roles",
  "authorized_policies",
];
const ROOT_KEY_FIELDS = new Set([
  "keyid",
  "entity_id",
  "organization_id",
  "signature_scheme",
  "public_key_spki_base64",
]);
const ROOT_ROLE_NAMES = new Set([
  "ledger-observer",
  "ledger-operator",
  "ledger-witness",
  "quorum-reviewer",
  "root",
]);
const ROOT_ROLE_FIELDS = new Set([
  "keyids",
  "signature_threshold",
  "minimum_distinct_organizations",
]);
const ROOT_SIGNATURE_FIELDS = new Set([
  "keyid",
  "signer_id",
  "signature_scheme",
  "signature_base64",
]);

function invariant(condition, message) {
  if (!condition) throw new Error(message);
}

function invariantNodeVersion() {
  const major = Number.parseInt(process.versions.node.split(".", 1)[0], 10);
  if (!Number.isSafeInteger(major) || major < 18) {
    throw new Error("the independent RootViewQuorum runner requires Node.js 18 or newer");
  }
}

function exactFields(value, fields, label) {
  invariant(isObject(value), `${label} must be an object`);
  const actual = Object.keys(value).sort();
  const expected = [...fields].sort();
  invariant(JSON.stringify(actual) === JSON.stringify(expected), `${label} fields are not exact`);
}

function isObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

function isPositiveInteger(value) {
  return Number.isSafeInteger(value) && value > 0;
}

function canonicalJson(value) {
  if (value === null || typeof value === "boolean" || typeof value === "string") {
    return JSON.stringify(value);
  }
  if (typeof value === "number") {
    invariant(Number.isSafeInteger(value), "canonical JSON accepts only safe finite integers here");
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`;
  invariant(isObject(value), "value is not canonical JSON data");
  return `{${Object.keys(value)
    .sort()
    .map((key) => `${JSON.stringify(key)}:${canonicalJson(value[key])}`)
    .join(",")}}`;
}

function sha256Bytes(value) {
  return createHash("sha256").update(value).digest("hex");
}

function canonicalSha256(value) {
  return sha256Bytes(Buffer.from(canonicalJson(value), "utf8"));
}

function without(value, field) {
  const copy = structuredClone(value);
  delete copy[field];
  return copy;
}

function strictBase64(value, label) {
  invariant(
    typeof value === "string" && value.length > 0 && value.length % 4 === 0,
    `${label} is not canonical base64`,
  );
  invariant(/^[A-Za-z0-9+/]*={0,2}$/.test(value), `${label} is not canonical base64`);
  const decoded = Buffer.from(value, "base64");
  invariant(decoded.toString("base64") === value, `${label} is not canonical base64`);
  return decoded;
}

function publicKey(descriptor, keyField, label) {
  const encoded = descriptor.public_key_spki_base64;
  const der = strictBase64(encoded, `${label}.public_key_spki_base64`);
  invariant(sha256Bytes(der) === descriptor[keyField], `${label} key digest does not match`);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  invariant(key.asymmetricKeyType === "ed25519", `${label} key is not Ed25519`);
  return key;
}

function verifyEd25519(payload, signature, descriptor, keyField, label) {
  const key = publicKey(descriptor, keyField, label);
  const raw = strictBase64(signature.signature_base64, `${label}.signature_base64`);
  invariant(raw.length === 64, `${label} signature must be 64 bytes`);
  invariant(
    verifySignature(null, Buffer.from(canonicalJson(payload), "utf8"), key, raw),
    `${label} Ed25519 signature is invalid`,
  );
}

function readBoundedJson(path) {
  const stat = lstatSync(path);
  invariant(stat.isFile() && !stat.isSymbolicLink(), `${path} must be a regular file`);
  invariant(stat.size <= MAX_FILE_BYTES, `${path} exceeds ${MAX_FILE_BYTES} bytes`);
  const raw = readFileSync(path);
  const value = JSON.parse(raw.toString("utf8"));
  invariant(isObject(value), `${path} JSON root must be an object`);
  return { raw, value };
}

function walkFiles(root, directory = root, result = []) {
  for (const name of readdirSync(directory).sort()) {
    const path = join(directory, name);
    const stat = lstatSync(path);
    invariant(!stat.isSymbolicLink(), `vector pack contains symbolic link ${relative(root, path)}`);
    if (stat.isDirectory()) walkFiles(root, path, result);
    else if (stat.isFile()) result.push(relative(root, path).split(sep).join("/"));
    else throw new Error(`vector pack contains a non-regular entry ${relative(root, path)}`);
  }
  return result;
}

function validateManifest(root) {
  const { value: manifest } = readBoundedJson(join(root, MANIFEST));
  invariant(manifest.vector_version === VECTOR_VERSION, "unsupported vector version");
  invariant(
    manifest.root_view_protocol_version === ROOT_VIEW_VERSION,
    "unsupported RootViewQuorum version",
  );
  invariant(
    manifest.manifest_sha256 === EXPECTED_MANIFEST_SHA256,
    "manifest digest does not identify immutable known-answer v1",
  );
  invariant(
    canonicalSha256(without(manifest, "manifest_sha256")) === manifest.manifest_sha256,
    "manifest digest does not recompute",
  );
  invariant(isObject(manifest.file_sha256), "manifest file_sha256 must be an object");
  const declared = Object.keys(manifest.file_sha256).sort();
  invariant(declared.length === 21, "manifest must bind exactly 21 vector artifacts");
  for (const name of declared) {
    invariant(SAFE_PATH.test(name) && !name.includes(".."), `unsafe vector path ${name}`);
    invariant(DIGEST.test(manifest.file_sha256[name]), `invalid file digest for ${name}`);
    const { raw } = readBoundedJson(join(root, name));
    invariant(sha256Bytes(raw) === manifest.file_sha256[name], `${name} file digest mismatch`);
  }
  const allowed = new Set([...declared, MANIFEST, "README.md"]);
  const unexpected = walkFiles(root).filter((name) => !allowed.has(name));
  invariant(unexpected.length === 0, `unexpected files: ${unexpected.join(", ")}`);
  invariant(Array.isArray(manifest.cases), "manifest cases must be an array");
  invariant(
    JSON.stringify(manifest.cases.map((item) => item.case_id)) ===
      JSON.stringify(EXPECTED_CASE_IDS),
    "manifest cases do not match immutable v1 ordering",
  );
  return manifest;
}

function validatePolicy(policy) {
  exactFields(policy, POLICY_FIELDS, "root-view policy");
  invariant(policy.schema_version === 1, "root-view policy schema is unsupported");
  invariant(
    policy.policy_type === "dspy-security-bench-assurance-root-view-policy" &&
      policy.protocol_version === ROOT_VIEW_VERSION,
    "root-view policy metadata is unsupported",
  );
  invariant(IDENTIFIER.test(policy.quorum_id), "root-view quorum_id is invalid");
  invariant(typeof policy.trust_domain === "string" && policy.trust_domain.length > 0, "trust domain is invalid");
  invariant(Array.isArray(policy.observers) && policy.observers.length >= 2, "observers are invalid");
  const ids = new Set();
  const keys = new Set();
  const organizations = new Set();
  for (const [index, observer] of policy.observers.entries()) {
    exactFields(observer, OBSERVER_FIELDS, `observers[${index}]`);
    invariant(IDENTIFIER.test(observer.entity_id), `observers[${index}] entity_id is invalid`);
    invariant(
      IDENTIFIER.test(observer.organization_id),
      `observers[${index}] organization_id is invalid`,
    );
    invariant(DIGEST.test(observer.public_key_sha256), `observers[${index}] digest is invalid`);
    publicKey(observer, "public_key_sha256", `observers[${index}]`);
    invariant(!ids.has(observer.entity_id), `duplicate observer ${observer.entity_id}`);
    invariant(!keys.has(observer.public_key_sha256), "duplicate observer key");
    ids.add(observer.entity_id);
    keys.add(observer.public_key_sha256);
    organizations.add(observer.organization_id);
  }
  invariant(
    JSON.stringify(policy.observers.map((item) => item.entity_id)) ===
      JSON.stringify([...ids].sort()),
    "observers are not sorted",
  );
  invariant(
    isPositiveInteger(policy.minimum_observers) &&
      policy.minimum_observers >= 2 &&
      policy.minimum_observers <= ids.size,
    "minimum observer threshold is invalid",
  );
  invariant(
    isPositiveInteger(policy.minimum_distinct_organizations) &&
      policy.minimum_distinct_organizations >= 2 &&
      policy.minimum_distinct_organizations <= organizations.size,
    "minimum organization threshold is invalid",
  );
  invariant(
    canonicalSha256(without(policy, "policy_sha256")) === policy.policy_sha256,
    "root-view policy digest does not recompute",
  );
  return new Map(policy.observers.map((item) => [item.entity_id, item]));
}

function validateRoot(root) {
  exactFields(root, ROOT_FIELDS, "trust root");
  invariant(
    root.schema_version === 1 &&
      root.root_type === "dspy-security-bench-assurance-trust-root" &&
      root.protocol_version === ROOT_VERSION,
    "trust-root metadata is unsupported",
  );
  invariant(typeof root.trust_domain === "string" && root.trust_domain.length > 0, "trust domain is invalid");
  invariant(isPositiveInteger(root.version), "trust-root version is invalid");
  invariant(Number.isSafeInteger(root.issued_at) && root.issued_at >= 0, "issued_at is invalid");
  invariant(Number.isSafeInteger(root.expires_at) && root.expires_at > root.issued_at, "expires_at is invalid");
  invariant(
    root.version === 1
      ? root.previous_root_sha256 === null && root.previous_root_signatures.length === 0
      : DIGEST.test(root.previous_root_sha256) && root.previous_root_signatures.length > 0,
    "trust-root predecessor metadata is invalid",
  );
  invariant(Array.isArray(root.keys) && root.keys.length > 0, "trust-root keys are invalid");
  const keys = new Map();
  for (const [index, key] of root.keys.entries()) {
    exactFields(key, ROOT_KEY_FIELDS, `root.keys[${index}]`);
    invariant(key.signature_scheme === "ed25519", "Node vector runner supports Ed25519 roots only");
    invariant(DIGEST.test(key.keyid), `root.keys[${index}] keyid is invalid`);
    invariant(IDENTIFIER.test(key.entity_id), `root.keys[${index}] entity_id is invalid`);
    invariant(IDENTIFIER.test(key.organization_id), `root.keys[${index}] organization_id is invalid`);
    publicKey(key, "keyid", `root.keys[${index}]`);
    invariant(!keys.has(key.keyid), `duplicate root key ${key.keyid}`);
    keys.set(key.keyid, key);
  }
  invariant(
    JSON.stringify(root.keys.map((item) => item.keyid)) === JSON.stringify([...keys.keys()].sort()),
    "trust-root keys are not sorted",
  );
  exactFields(root.roles, ROOT_ROLE_NAMES, "trust-root roles");
  for (const [name, role] of Object.entries(root.roles)) {
    exactFields(role, ROOT_ROLE_FIELDS, `root role ${name}`);
    invariant(Array.isArray(role.keyids) && role.keyids.length > 0, `root role ${name} keyids are invalid`);
    invariant(
      JSON.stringify(role.keyids) === JSON.stringify([...new Set(role.keyids)].sort()),
      `root role ${name} keyids are not sorted and unique`,
    );
    invariant(role.keyids.every((keyid) => keys.has(keyid)), `root role ${name} has unknown keys`);
    invariant(
      isPositiveInteger(role.signature_threshold) && role.signature_threshold <= role.keyids.length,
      `root role ${name} signature threshold is invalid`,
    );
    const roleOrganizations = new Set(role.keyids.map((keyid) => keys.get(keyid).organization_id));
    invariant(
      isPositiveInteger(role.minimum_distinct_organizations) &&
        role.minimum_distinct_organizations <= roleOrganizations.size,
      `root role ${name} organization threshold is invalid`,
    );
  }
  invariant(Array.isArray(root.authorized_policies) && root.authorized_policies.length > 0, "authorized policies are invalid");
  invariant(Array.isArray(root.signatures), "root signatures must be an array");
  invariant(
    canonicalSha256(without(root, "root_sha256")) === root.root_sha256,
    "trust-root digest does not recompute",
  );
  const signedPayload = Object.fromEntries(ROOT_SIGNED_FIELDS.map((field) => [field, root[field]]));
  const rootRole = root.roles.root;
  const valid = new Set();
  const organizations = new Set();
  for (const [index, signature] of root.signatures.entries()) {
    exactFields(signature, ROOT_SIGNATURE_FIELDS, `root.signatures[${index}]`);
    const descriptor = keys.get(signature.keyid);
    if (!descriptor || !rootRole.keyids.includes(signature.keyid)) continue;
    invariant(signature.signer_id === descriptor.entity_id, "root signature signer is invalid");
    invariant(signature.signature_scheme === descriptor.signature_scheme, "root signature scheme is invalid");
    verifyEd25519(signedPayload, signature, descriptor, "keyid", `root.signatures[${index}]`);
    valid.add(signature.keyid);
    organizations.add(descriptor.organization_id);
  }
  invariant(valid.size >= rootRole.signature_threshold, "current root signature threshold is unmet");
  invariant(
    organizations.size >= rootRole.minimum_distinct_organizations,
    "current root organization threshold is unmet",
  );
}

function inspectReceipt(policy, observerMap, candidate, nonce, receipt, index) {
  const categories = { shape: [], request: [], auth: [], root: [] };
  const capture = (category, work) => {
    try {
      work();
    } catch (error) {
      categories[category].push(error.message);
    }
  };
  capture("shape", () => {
    exactFields(receipt, RECEIPT_FIELDS, `receipts[${index}]`);
    exactFields(receipt.statement, STATEMENT_FIELDS, `receipts[${index}].statement`);
    exactFields(
      receipt.observer_signature,
      OBSERVER_SIGNATURE_FIELDS,
      `receipts[${index}].observer_signature`,
    );
    invariant(receipt.statement.protocol_version === ROOT_VIEW_VERSION, "statement version is invalid");
    invariant(receipt.statement.root_view_policy_sha256 === policy.policy_sha256, "statement policy does not match");
    invariant(receipt.statement.trust_domain === policy.trust_domain, "statement trust domain does not match");
    invariant(DIGEST.test(receipt.statement.candidate_root_sha256), "statement candidate digest is invalid");
    invariant(NONCE.test(receipt.statement.request_nonce), "statement nonce is invalid");
    invariant(DIGEST.test(receipt.statement.observed_root_sha256), "observed root digest is invalid");
    invariant(isPositiveInteger(receipt.statement.observed_root_version), "observed root version is invalid");
  });
  capture("request", () => {
    invariant(receipt.statement.candidate_root_sha256 === candidate.root_sha256, "candidate root does not match");
    invariant(receipt.statement.request_nonce === nonce, "nonce does not match the request");
  });
  capture("auth", () => {
    const observer = observerMap.get(receipt.statement.observer_id);
    invariant(observer, "observer is not policy-authorized");
    invariant(
      receipt.statement.observer_organization_id === observer.organization_id,
      "observer organization does not match",
    );
    invariant(
      receipt.statement.observer_key_sha256 === observer.public_key_sha256,
      "observer key does not match",
    );
    invariant(receipt.observer_signature.keyid === observer.public_key_sha256, "signature keyid does not match");
    invariant(receipt.observer_signature.signer_id === observer.entity_id, "signature signer does not match");
    verifyEd25519(
      receipt.statement,
      receipt.observer_signature,
      observer,
      "public_key_sha256",
      `receipts[${index}].observer_signature`,
    );
  });
  capture("root", () => {
    validateRoot(receipt.observed_root);
    invariant(receipt.observed_root.trust_domain === policy.trust_domain, "observed root trust domain does not match");
    invariant(
      receipt.observed_root.root_sha256 === receipt.statement.observed_root_sha256,
      "observed root digest does not match statement",
    );
    invariant(
      receipt.observed_root.version === receipt.statement.observed_root_version,
      "observed root version does not match statement",
    );
  });
  const errors = Object.values(categories).flat();
  let classification = "invalid";
  if (errors.length === 0) {
    if (receipt.statement.observed_root_version < candidate.version) classification = "lagging";
    else if (receipt.statement.observed_root_version > candidate.version) classification = "newer";
    else if (receipt.statement.observed_root_sha256 === candidate.root_sha256) classification = "matching";
    else classification = "same_version_conflict";
  }
  return { valid: errors.length === 0, classification, categories, statement: receipt.statement };
}

function evaluate(policy, candidate, receipts, expectedPolicySha256, nonce) {
  const failures = new Set();
  let observerMap;
  try {
    observerMap = validatePolicy(policy);
  } catch {
    failures.add("ARV002");
    observerMap = new Map();
  }
  try {
    validateRoot(candidate);
    invariant(candidate.trust_domain === policy.trust_domain, "candidate domain mismatch");
  } catch {
    failures.add("ARV003");
  }
  const policyPinned = policy.policy_sha256 === expectedPolicySha256;
  if (!policyPinned) failures.add("ARV001");
  const results = receipts.map((receipt, index) =>
    inspectReceipt(policy, observerMap, candidate, nonce, receipt, index),
  );
  if (results.some((item) => item.categories.shape.length)) failures.add("ARV004");
  if (results.some((item) => item.categories.request.length)) failures.add("ARV005");
  if (results.some((item) => item.categories.auth.length)) failures.add("ARV006");
  if (results.some((item) => item.categories.root.length)) failures.add("ARV007");
  const valid = results.filter((item) => item.valid);
  const observerIds = valid.map((item) => item.statement.observer_id);
  const uniqueObservers = new Set(observerIds).size === observerIds.length;
  const matching = valid.filter((item) => item.classification === "matching");
  const matchingIds = new Set(matching.map((item) => item.statement.observer_id));
  const matchingOrganizations = new Set(
    matching.map((item) => item.statement.observer_organization_id),
  );
  const lagging = valid.filter((item) => item.classification === "lagging");
  const newer = valid.filter((item) => item.classification === "newer");
  const conflicts = valid.filter((item) => item.classification === "same_version_conflict");
  const enoughObservers = uniqueObservers && matchingIds.size >= policy.minimum_observers;
  const enoughOrganizations =
    matchingOrganizations.size >= policy.minimum_distinct_organizations;
  if (!uniqueObservers || matchingIds.size < policy.minimum_observers) failures.add("ARV008");
  if (!enoughOrganizations) failures.add("ARV009");
  if (conflicts.length || newer.length) failures.add("ARV010");
  const evidenceErrors = ["ARV002", "ARV003", "ARV004", "ARV006", "ARV007"].some(
    (rule) => failures.has(rule),
  );
  let status;
  if (evidenceErrors) status = "invalid_root_view_evidence";
  else if (!policyPinned) status = "root_view_policy_not_pinned";
  else if (failures.has("ARV005")) status = "root_view_request_mismatch";
  else if (!uniqueObservers) status = "insufficient_root_observers";
  else if (conflicts.length) status = "same_version_root_conflict";
  else if (newer.length) status = "newer_root_reported";
  else if (!enoughObservers) status = "insufficient_root_observers";
  else if (!enoughOrganizations) status = "insufficient_root_observer_diversity";
  else status = "root_view_corroborated";
  return {
    status,
    summary: {
      status,
      candidate_root_version: candidate.version,
      submitted_receipts: receipts.length,
      valid_receipts: valid.length,
      distinct_observers: new Set(observerIds).size,
      matching_observers: matchingIds.size,
      matching_organizations: matchingOrganizations.size,
      lagging_observers: lagging.length,
      newer_root_reports: newer.length,
      same_version_conflicts: conflicts.length,
      passed_checks: 10 - failures.size,
      failed_checks: failures.size,
      content_fields_processed: 0,
      network_requests: 0,
      roots_installed: 0,
      automatic_actions: 0,
    },
  };
}

function verifySemanticReport(report) {
  const errors = [];
  try {
    invariant(report.protocol_version === ROOT_VIEW_VERSION, "unsupported RootViewQuorum report");
    invariant(
      canonicalSha256(without(report, "report_sha256")) === report.report_sha256,
      "report_sha256 does not recompute",
    );
    const computed = evaluate(
      report.root_view_policy,
      report.candidate_root,
      report.receipts,
      report.expectations.expected_policy_sha256,
      report.expectations.expected_request_nonce,
    );
    invariant(
      canonicalJson(computed.summary) === canonicalJson(report.summary),
      "RootViewQuorum report does not recompute exactly",
    );
  } catch (error) {
    errors.push(error.message);
  }
  return errors;
}

function load(root, name) {
  invariant(SAFE_PATH.test(name) && !name.includes(".."), `unsafe vector path ${name}`);
  return readBoundedJson(join(root, name)).value;
}

function run(root) {
  const manifest = validateManifest(root);
  const cases = [];
  for (const item of manifest.cases) {
    const report = load(root, item.report_file);
    const verifierErrors = verifySemanticReport(report);
    if (item.operation === "evaluate") {
      const policy = load(root, item.policy_file);
      const candidate = load(root, item.candidate_root_file);
      const receipts = item.receipt_files.map((name) => load(root, name));
      invariant(canonicalJson(policy) === canonicalJson(report.root_view_policy), `${item.case_id}: report policy differs from vector input`);
      invariant(canonicalJson(candidate) === canonicalJson(report.candidate_root), `${item.case_id}: report candidate differs from vector input`);
      invariant(canonicalJson(receipts) === canonicalJson(report.receipts), `${item.case_id}: report receipts differ from vector input`);
      const computed = evaluate(
        policy,
        candidate,
        receipts,
        item.expected_policy_sha256,
        item.expected_request_nonce,
      );
      invariant(computed.status === item.expected_status, `${item.case_id}: status mismatch`);
    }
    const accepted = verifierErrors.length === 0;
    invariant(
      accepted === item.expected_verifier_acceptance,
      `${item.case_id}: verifier acceptance mismatch (${verifierErrors.join("; ")})`,
    );
    if (item.expected_error_fragment !== null) {
      invariant(
        verifierErrors.some((message) => message.includes(item.expected_error_fragment)),
        `${item.case_id}: expected verifier error was not observed`,
      );
    }
    cases.push({ case_id: item.case_id, status: "passed", verifier_accepted: accepted });
  }
  return {
    implementation: "dspy-security-bench-root-view-node-v1",
    runtime: process.version,
    vector_version: manifest.vector_version,
    manifest_sha256: manifest.manifest_sha256,
    cases,
    summary: { passed: cases.length, failed: 0, automatic_actions: 0 },
  };
}

const scriptDirectory = resolve(fileURLToPath(new URL(".", import.meta.url)));
const defaultPack = resolve(scriptDirectory, "../root-view-quorum-v1");
const pack = resolve(process.argv[2] ?? defaultPack);

try {
  const result = run(pack);
  process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
} catch (error) {
  process.stderr.write(`[root-view-node] ${error.message}\n`);
  process.exitCode = 1;
}
