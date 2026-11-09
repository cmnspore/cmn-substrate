// Public deterministic test seeds only. Run with Node.js; no packages needed.
// URI hashes are structural placeholders; these cases test signatures, not trees.
import { createPrivateKey, createPublicKey, sign } from "node:crypto";
import { writeFileSync } from "node:fs";

const alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
function base58(bytes) {
  let value = BigInt("0x" + bytes.toString("hex"));
  let result = "";
  while (value) {
    result = alphabet[Number(value % 58n)] + result;
    value /= 58n;
  }
  for (const byte of bytes) {
    if (byte) break;
    result = "1" + result;
  }
  return result;
}

// These fixtures use finite integers and plain strings. Sorting object keys
// and JSON.stringify gives their RFC 8785 canonical JSON bytes.
function canonical(value) {
  if (Array.isArray(value)) return value.map(canonical);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map(key => [key, canonical(value[key])]));
  }
  return value;
}

function testKey(byte) {
  const seed = Buffer.alloc(32, byte);
  const privateKey = createPrivateKey({
    key: Buffer.concat([Buffer.from("302e020100300506032b657004220420", "hex"), seed]),
    format: "der", type: "pkcs8",
  });
  const publicKey = createPublicKey(privateKey).export({ format: "der", type: "spki" }).subarray(-32);
  return { seed_hex: seed.toString("hex"), public_key: "ed25519." + base58(publicKey), privateKey };
}
function signature(value, key) {
  return "ed25519." + base58(sign(null, Buffer.from(JSON.stringify(canonical(value))), key.privateKey));
}

const author = testKey(17), host = testKey(34);
const test_keys = Object.fromEntries(Object.entries({ author, host }).map(([name, key]) => [name, {
  seed_hex: key.seed_hex, public_key: key.public_key,
}]));
function spore(authorKey, hostKey, signedAt = 1000) {
  const core = {
    id: "signed-test", name: "Signed test", domain: "author.example", key: authorKey.public_key,
    synopsis: "Public conformance fixture", intent: ["test"], license: "MIT",
    mutations: [], bonds: [], size_bytes: 0,
    tree: { algorithm: "blob_tree_blake3_nfc", exclude_names: [], follow_rules: [] },
  };
  if (signedAt !== undefined) core.updated_at_epoch_ms = signedAt;
  const hostDomain = authorKey === hostKey ? "author.example" : "host.example";
  const capsule = {
    uri: `cmn://${hostDomain}/b3.3yMR7vZQ9hL2xKJdFtN8wPcB6sY1mXgU4eH5pTa2`,
    core, core_signature: signature(core, authorKey), dist: [{ type: "archive" }],
  };
  return { $schema: "https://cmn.dev/schemas/v1/spore.json", capsule, capsule_signature: signature(capsule, hostKey) };
}
const selfHosted = spore(author, author), replicated = spore(author, host);
const tamperedCore = structuredClone(replicated);
tamperedCore.capsule.core.synopsis = "Tampered";
const tamperedDist = structuredClone(replicated);
tamperedDist.capsule.dist = [{ type: "git", url: "https://host.example/tampered.git" }];
const capsuleCases = [
  ["self_hosted", selfHosted, author.public_key, author.public_key, true],
  ["replicated", replicated, author.public_key, host.public_key, true],
  ["swapped_keys", replicated, host.public_key, author.public_key, false],
  ["tampered_core", tamperedCore, author.public_key, host.public_key, false],
  ["tampered_dist", tamperedDist, author.public_key, host.public_key, false],
].map(([id, spore, author_key, host_key, expected_valid]) => ({ id, spore, author_key, host_key, expected_valid }));

const statement = {
  purpose: "cmn-key-rotation-v1", domain: "author.example", from: author.public_key, to: host.public_key,
  effective_serial: 2, retired_at_epoch_ms: 1000,
};
const capsules = [{ uri: "cmn://author.example", serial: 2, key: host.public_key, endpoints: [], history: [{
  key: author.public_key, status: "retired", retired_at_epoch_ms: 1000, replaced_by: host.public_key,
  effective_serial: 2, rotation_signature: signature(statement, author),
}] }];
const cmn = { $schema: "https://cmn.dev/schemas/v1/cmn.json", capsules, capsule_signature: signature(capsules, host) };
const rotationCases = [["before_retirement", 999, true], ["at_retirement", 1000, true], ["after_retirement", 1001, false], ["missing_signing_time", null, false]]
  .map(([id, timestamp, expected_valid]) => {
    const content = spore(author, author, timestamp);
    if (timestamp === null) {
      delete content.capsule.core.updated_at_epoch_ms;
      content.capsule.core_signature = signature(content.capsule.core, author);
      content.capsule_signature = signature(content.capsule, author);
    }
    return { id, cmn, spore: content, expected_valid };
  });
for (const [name, cases] of [["capsule_signed", capsuleCases], ["key_rotation_signed", rotationCases]]) {
  const document = { version: "cmn-conformance-v1", description: "Deterministic signatures from public test seeds; never use these keys outside tests.", test_keys, cases };
  writeFileSync(new URL(`vectors/${name}.json`, import.meta.url), JSON.stringify(document, null, 2) + "\n");
}
