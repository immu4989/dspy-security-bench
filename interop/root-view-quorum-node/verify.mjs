#!/usr/bin/env node

/**
 * Independent, zero-dependency Node.js runner for the immutable
 * AssuranceLedger RootViewQuorum v1 known-answer pack.
 *
 * This deliberately does not import or execute the Python reference verifier.
 */

import {
  constants as cryptoConstants,
  createHash,
  createPublicKey,
  verify as verifySignature,
} from "node:crypto";
import { lstatSync, readFileSync, readdirSync } from "node:fs";
import { join, relative, resolve, sep } from "node:path";
import { fileURLToPath } from "node:url";

const VECTOR_VERSION = "assuranceledger-root-view-vectors-v1";
const ROOT_VIEW_VERSION = "assuranceledger-root-view-quorum-v1";
const ROOT_VERSION = "assuranceledger-trust-root-v1";
const IMPLEMENTATION_ID = "dspy-security-bench-root-view-node-v1";
const IMPLEMENTATION_SHA256 = sha256Bytes(readFileSync(fileURLToPath(import.meta.url)));
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
const ROOT_POLICY_FIELDS = new Set(["policy_type", "policy_sha256"]);
const ROOT_SIGNATURE_FIELDS = new Set([
  "keyid",
  "signer_id",
  "signature_scheme",
  "signature_base64",
]);
const AUTHORIZED_POLICY_TYPES = new Set([
  "dspy-security-bench-assurance-ledger-observer-policy",
  "dspy-security-bench-assurance-ledger-policy",
  "dspy-security-bench-assurance-quorum-policy",
  "dspy-security-bench-assurance-trust-recovery-attestation-policy",
  "dspy-security-bench-assurance-trust-recovery-policy",
]);
const REPORT_TYPE = "AssuranceLedger RootViewQuorum / Independently observed root distribution";
const ANALYZER = "deterministic-independent-root-view-analyzer-v1";
const CHECKS = [
  ["ARV001", "The exact root-view policy is independently pinned"],
  ["ARV002", "The root-view policy structure, keys, and digest are valid"],
  ["ARV003", "The candidate root is self-consistent and in the expected domain"],
  ["ARV004", "Every receipt has the exact root-view statement shape"],
  ["ARV005", "Every receipt binds the candidate root and fresh request nonce"],
  ["ARV006", "Every observer identity, organization, key, and signature verify"],
  ["ARV007", "Every embedded observed root recomputes and matches its statement"],
  ["ARV008", "The minimum number of unique matching observers is satisfied"],
  ["ARV009", "The matching-observer organization threshold is satisfied"],
  ["ARV010", "No authenticated self-consistent same-version conflict or higher root is reported"],
];
const CLAIM_BOUNDARY =
  "RootViewQuorum verifies policy-pinned Ed25519 observations from distinct declared organizations over one candidate AssuranceTrustRoot and fresh caller nonce. It corroborates only the views supplied for that challenge and makes authenticated observations of a self-consistent same-version conflict or higher-version root non-outvotable. A passing report is bounded distribution-view evidence, not proof of global freshness or root trust.";
const LIMITATIONS = [
  "Observer and organization identifiers are policy assertions; signatures do not prove legal identity, operational independence, complete monitoring, or secure key custody.",
  "Freshness depends on the caller generating and independently retaining an unpredictable nonce and the exact pinned observer-policy digest.",
  "A higher-version receipt proves that an authorized observer signed a self-consistent root object; it does not by itself prove continuity from the candidate or that the root was globally deployed.",
  "A passing quorum cannot exclude an undisclosed view held outside the selected observers, a partition affecting all selected observers, or collusion sufficient to satisfy the policy.",
  "The protocol is not TUF, C2SP transparency-witness, Key Transparency, SCITT, PKI, trust-store, or software-update compatibility.",
  "The analyzer performs no network access, root installation, key operation, notification, revocation, deployment, authorization, risk acceptance, or automatic remediation.",
];

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

function publicKey(descriptor, keyField, label, scheme = "ed25519") {
  const encoded = descriptor.public_key_spki_base64;
  const der = strictBase64(encoded, `${label}.public_key_spki_base64`);
  invariant(sha256Bytes(der) === descriptor[keyField], `${label} key digest does not match`);
  const key = createPublicKey({ key: der, format: "der", type: "spki" });
  if (scheme === "ed25519") {
    invariant(key.asymmetricKeyType === "ed25519", `${label} key is not Ed25519`);
  } else if (scheme === "ecdsa-sha2-nistp256") {
    invariant(
      key.asymmetricKeyType === "ec" && key.asymmetricKeyDetails?.namedCurve === "prime256v1",
      `${label} key is not NIST P-256`,
    );
  } else if (scheme === "rsassa-pss-sha256") {
    invariant(
      key.asymmetricKeyType === "rsa" && key.asymmetricKeyDetails?.modulusLength >= 2048,
      `${label} RSA key is smaller than 2048 bits`,
    );
  } else {
    throw new Error(`${label} signature scheme is unsupported`);
  }
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

function verifyRootSignature(payload, signature, descriptor, label) {
  const scheme = descriptor.signature_scheme;
  const key = publicKey(descriptor, "keyid", label, scheme);
  const raw = strictBase64(signature.signature_base64, `${label}.signature_base64`);
  const data = Buffer.from(canonicalJson(payload), "utf8");
  let accepted;
  if (scheme === "ed25519") {
    invariant(raw.length === 64, `${label} signature must be 64 bytes`);
    accepted = verifySignature(null, data, key, raw);
  } else if (scheme === "ecdsa-sha2-nistp256") {
    accepted = verifySignature("sha256", data, key, raw);
  } else if (scheme === "rsassa-pss-sha256") {
    accepted = verifySignature(
      "sha256",
      data,
      {
        key,
        padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
        saltLength: 32,
      },
      raw,
    );
  } else {
    throw new Error(`${label} signature scheme is unsupported`);
  }
  invariant(accepted, `${label} cryptographic signature is invalid`);
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
  invariant(
    typeof policy.trust_domain === "string" &&
      policy.trust_domain.trim().length > 0 &&
      policy.trust_domain.length <= 300,
    "trust domain is invalid",
  );
  invariant(
    Array.isArray(policy.observers) &&
      policy.observers.length >= 2 &&
      policy.observers.length <= 50,
    "observers are invalid",
  );
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
  invariant(policy.claim_boundary === CLAIM_BOUNDARY, "root-view claim boundary is invalid");
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
  invariant(
    typeof root.trust_domain === "string" &&
      root.trust_domain.trim().length > 0 &&
      root.trust_domain.length <= 300,
    "trust domain is invalid",
  );
  invariant(isPositiveInteger(root.version), "trust-root version is invalid");
  invariant(Number.isSafeInteger(root.issued_at) && root.issued_at >= 0, "issued_at is invalid");
  invariant(Number.isSafeInteger(root.expires_at) && root.expires_at > root.issued_at, "expires_at is invalid");
  invariant(
    root.version === 1
      ? root.previous_root_sha256 === null && root.previous_root_signatures.length === 0
      : DIGEST.test(root.previous_root_sha256) && root.previous_root_signatures.length > 0,
    "trust-root predecessor metadata is invalid",
  );
  invariant(
    Array.isArray(root.keys) && root.keys.length > 0 && root.keys.length <= 100,
    "trust-root keys are invalid",
  );
  const keys = new Map();
  const entities = new Set();
  for (const [index, key] of root.keys.entries()) {
    exactFields(key, ROOT_KEY_FIELDS, `root.keys[${index}]`);
    invariant(
      ["ed25519", "ecdsa-sha2-nistp256", "rsassa-pss-sha256"].includes(
        key.signature_scheme,
      ),
      "trust-root signature scheme is unsupported",
    );
    invariant(DIGEST.test(key.keyid), `root.keys[${index}] keyid is invalid`);
    invariant(IDENTIFIER.test(key.entity_id), `root.keys[${index}] entity_id is invalid`);
    invariant(IDENTIFIER.test(key.organization_id), `root.keys[${index}] organization_id is invalid`);
    publicKey(key, "keyid", `root.keys[${index}]`, key.signature_scheme);
    invariant(!keys.has(key.keyid), `duplicate root key ${key.keyid}`);
    invariant(!entities.has(key.entity_id), `duplicate root entity ${key.entity_id}`);
    keys.set(key.keyid, key);
    entities.add(key.entity_id);
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
  invariant(
    Array.isArray(root.authorized_policies) &&
      root.authorized_policies.length > 0 &&
      root.authorized_policies.length <= 100,
    "authorized policies are invalid",
  );
  const policyIdentities = new Set();
  let previousPolicyIdentity = "";
  for (const [index, policy] of root.authorized_policies.entries()) {
    exactFields(policy, ROOT_POLICY_FIELDS, `authorized_policies[${index}]`);
    invariant(
      AUTHORIZED_POLICY_TYPES.has(policy.policy_type),
      `authorized_policies[${index}] type is unsupported`,
    );
    invariant(DIGEST.test(policy.policy_sha256), `authorized_policies[${index}] digest is invalid`);
    const identity = `${policy.policy_type}\u0000${policy.policy_sha256}`;
    invariant(identity >= previousPolicyIdentity, "authorized policies are not sorted");
    invariant(!policyIdentities.has(identity), `authorized_policies[${index}] is duplicated`);
    policyIdentities.add(identity);
    previousPolicyIdentity = identity;
  }
  for (const field of ["signatures", "previous_root_signatures"]) {
    const signatures = root[field];
    invariant(Array.isArray(signatures) && signatures.length <= 100, `${field} is invalid`);
    const keyids = [];
    for (const [index, signature] of signatures.entries()) {
      exactFields(signature, ROOT_SIGNATURE_FIELDS, `${field}[${index}]`);
      invariant(DIGEST.test(signature.keyid), `${field}[${index}] keyid is invalid`);
      invariant(IDENTIFIER.test(signature.signer_id), `${field}[${index}] signer is invalid`);
      invariant(
        ["ed25519", "ecdsa-sha2-nistp256", "rsassa-pss-sha256"].includes(
          signature.signature_scheme,
        ),
        `${field}[${index}] scheme is unsupported`,
      );
      strictBase64(signature.signature_base64, `${field}[${index}].signature_base64`);
      keyids.push(signature.keyid);
    }
    invariant(
      JSON.stringify(keyids) === JSON.stringify([...new Set(keyids)].sort()),
      `${field} is not sorted and unique`,
    );
  }
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
    verifyRootSignature(signedPayload, signature, descriptor, `root.signatures[${index}]`);
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
  const capture = (category, work, fallback) => {
    try {
      work();
    } catch (error) {
      categories[category].push(fallback ?? error.message);
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
  if (receipt.statement?.candidate_root_sha256 !== candidate.root_sha256) {
    categories.request.push(`receipts[${index}].statement candidate root does not match`);
  }
  if (receipt.statement?.request_nonce !== nonce) {
    categories.request.push(`receipts[${index}].statement nonce does not match the request`);
  }
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
  }, `receipts[${index}].observer_signature Ed25519 signature is invalid`);
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
  const statement = receipt.statement ?? {};
  return {
    valid: errors.length === 0,
    classification,
    categories,
    statement,
    receiptResult: {
      receipt_index: index,
      observer_id: statement.observer_id ?? null,
      observer_organization_id: statement.observer_organization_id ?? null,
      observed_root_sha256: statement.observed_root_sha256 ?? null,
      observed_root_version: isPositiveInteger(statement.observed_root_version)
        ? statement.observed_root_version
        : null,
      classification,
      status: errors.length === 0 ? "valid" : "invalid",
      errors,
    },
  };
}

function evaluate(policy, candidate, receipts, expectedPolicySha256, nonce) {
  const ruleErrors = Object.fromEntries(CHECKS.map(([rule]) => [rule, []]));
  const policyErrors = [];
  const candidateErrors = [];
  let observerMap;
  try {
    observerMap = validatePolicy(policy);
  } catch (error) {
    policyErrors.push(error.message);
    ruleErrors.ARV002.push(error.message);
    observerMap = new Map();
  }
  try {
    validateRoot(candidate);
    invariant(candidate.trust_domain === policy.trust_domain, "candidate domain mismatch");
  } catch (error) {
    candidateErrors.push(error.message);
    ruleErrors.ARV003.push(error.message);
  }
  const policyPinned = policy.policy_sha256 === expectedPolicySha256;
  if (!policyPinned) {
    ruleErrors.ARV001.push(
      "root-view policy digest does not match the independently supplied pin",
    );
  }
  const results = receipts.map((receipt, index) =>
    inspectReceipt(policy, observerMap, candidate, nonce, receipt, index),
  );
  for (const result of results) {
    ruleErrors.ARV004.push(...result.categories.shape);
    ruleErrors.ARV005.push(...result.categories.request);
    ruleErrors.ARV006.push(...result.categories.auth);
    ruleErrors.ARV007.push(...result.categories.root);
  }
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
  if (!uniqueObservers) {
    ruleErrors.ARV008.push("one observer submitted more than one valid receipt");
  }
  if (matchingIds.size < policy.minimum_observers) {
    ruleErrors.ARV008.push("minimum matching-observer threshold is not met");
  }
  if (!enoughOrganizations) {
    ruleErrors.ARV009.push(
      "minimum distinct matching-observer organization threshold is not met",
    );
  }
  if (conflicts.length) {
    ruleErrors.ARV010.push(
      "an authorized observer reported a different self-consistent root at the candidate version",
    );
  }
  if (newer.length) {
    ruleErrors.ARV010.push(
      "an authorized observer reported a self-consistent root above the candidate version",
    );
  }
  for (const rule of Object.keys(ruleErrors)) ruleErrors[rule] = [...new Set(ruleErrors[rule])];
  const failures = new Set(
    Object.entries(ruleErrors)
      .filter(([, errors]) => errors.length > 0)
      .map(([rule]) => rule),
  );
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
  const findings = CHECKS.map(([rule_id, title]) => ({
    rule_id,
    title,
    status: ruleErrors[rule_id].length === 0 ? "passed" : "failed",
    detail: ruleErrors[rule_id].length === 0 ? "verified" : ruleErrors[rule_id].join("; "),
    receipt_indexes: receipts.map((_, index) => index),
  }));
  const report = {
    schema_version: 1,
    report_type: REPORT_TYPE,
    protocol_version: ROOT_VIEW_VERSION,
    analyzer: ANALYZER,
    root_view_policy: structuredClone(policy),
    candidate_root: structuredClone(candidate),
    expectations: {
      expected_policy_sha256: expectedPolicySha256,
      expected_request_nonce: nonce,
    },
    receipts: structuredClone(receipts),
    policy_errors: policyErrors,
    candidate_errors: candidateErrors,
    receipt_results: results.map((item) => item.receiptResult),
    findings,
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
    claim_boundary: CLAIM_BOUNDARY,
    limitations: structuredClone(LIMITATIONS),
  };
  report.report_sha256 = canonicalSha256(report);
  return { status, summary: report.summary, report };
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
    invariant(canonicalJson(computed.report) === canonicalJson(report), "RootViewQuorum report does not recompute exactly");
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
    let observedStatus = report.summary?.status ?? null;
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
      observedStatus = computed.status;
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
    cases.push({
      case_id: item.case_id,
      status: "passed",
      expected_status: item.expected_status,
      observed_status: observedStatus,
      verifier_accepted: accepted,
    });
  }
  return {
    implementation: IMPLEMENTATION_ID,
    implementation_sha256: IMPLEMENTATION_SHA256,
    runtime: process.version,
    vector_version: manifest.vector_version,
    manifest_sha256: manifest.manifest_sha256,
    cases,
    summary: { passed: cases.length, failed: 0, automatic_actions: 0 },
  };
}

const scriptDirectory = resolve(fileURLToPath(new URL(".", import.meta.url)));
const defaultPack = resolve(scriptDirectory, "../root-view-quorum-v1");

try {
  if (process.argv[2] === "--report") {
    invariant(process.argv.length === 4, "usage: verify.mjs --report REPORT.json");
    const path = resolve(process.argv[3]);
    const { value: report } = readBoundedJson(path);
    const errors = verifySemanticReport(report);
    const result = {
      implementation: IMPLEMENTATION_ID,
      implementation_sha256: IMPLEMENTATION_SHA256,
      runtime: process.version,
      protocol_version: ROOT_VIEW_VERSION,
      report_sha256: report.report_sha256 ?? null,
      accepted: errors.length === 0,
      evidence_status: report.summary?.status ?? null,
      errors,
      automatic_actions: 0,
    };
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
    if (errors.length) process.exitCode = 1;
  } else {
    invariant(process.argv.length <= 3, "usage: verify.mjs [PACK_DIR]");
    const pack = resolve(process.argv[2] ?? defaultPack);
    const result = run(pack);
    process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
  }
} catch (error) {
  process.stderr.write(`[root-view-node] ${error.message}\n`);
  process.exitCode = 1;
}
