const fs = require("fs");
const crypto = require("crypto");

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function verifyEd25519(data, signature, publicKeyPem) {
  return crypto.verify(null, data, publicKeyPem, signature);
}

function readVint(buffer, offset) {
  const first = buffer[offset];
  let mask = 0x80;
  let length = 1;
  while (length <= 8 && !(first & mask)) {
    mask >>= 1;
    length += 1;
  }
  let value = first & (mask - 1);
  for (let i = 1; i < length; i += 1) {
    value = (value << 8) | buffer[offset + i];
  }
  return { value, length };
}

function readElementId(buffer, offset) {
  const first = buffer[offset];
  let mask = 0x80;
  let length = 1;
  while (length <= 4 && !(first & mask)) {
    mask >>= 1;
    length += 1;
  }
  let value = 0;
  for (let i = 0; i < length; i += 1) {
    value = (value << 8) | buffer[offset + i];
  }
  return { value, length };
}

function iterElements(buffer, offset, size) {
  const elements = [];
  const end = offset + size;
  let cursor = offset;
  while (cursor < end) {
    const id = readElementId(buffer, cursor);
    cursor += id.length;
    const vint = readVint(buffer, cursor);
    cursor += vint.length;
    elements.push({ id: id.value, start: cursor, size: vint.value });
    cursor += vint.value;
  }
  return elements;
}

function extractOriginPayloadsMkv(filePath) {
  const data = fs.readFileSync(filePath);
  const tagsId = 0x1254c367;
  const tagId = 0x7373;
  const simpleTagId = 0x67c8;
  const tagNameId = 0x45a3;
  const tagStringId = 0x4487;

  try {
    for (const element of iterElements(data, 0, data.length)) {
      if (element.id !== tagsId) {
        continue;
      }
      for (const tag of iterElements(data, element.start, element.size)) {
        if (tag.id !== tagId) {
          continue;
        }
        for (const simple of iterElements(data, tag.start, tag.size)) {
          if (simple.id !== simpleTagId) {
            continue;
          }
          let name = null;
          let value = null;
          for (const item of iterElements(data, simple.start, simple.size)) {
            if (item.id === tagNameId) {
              name = data.slice(item.start, item.start + item.size);
            } else if (item.id === tagStringId) {
              value = data.slice(item.start, item.start + item.size);
            }
          }
          if (name && name.toString("utf8") === "ORIGIN" && value) {
            return [value];
          }
        }
      }
    }
  } catch (err) {
    // fallback to heuristic search
  }

  const index = data.indexOf(Buffer.from("ORIGIN", "utf8"));
  if (index === -1) {
    return [];
  }
  return [data.slice(index + 6)];
}

function validatePayload(payloadBytes) {
  let payloadJson;
  try {
    payloadJson = JSON.parse(payloadBytes.toString("utf8"));
  } catch (err) {
    return { ok: false, reason: "payload_invalid_json" };
  }
  const payload = payloadJson.payload || {};
  const required = new Set([
    "bundle.json",
    "bundle.sig",
    "manifest.json",
    "signature.ed25519",
    "seal.json",
    "seal.ed25519",
    "public_key.ed25519",
  ]);
  for (const key of required) {
    if (!payload[key]) {
      return { ok: false, reason: "payload_missing_keys" };
    }
  }

  const bundleManifest = JSON.parse(Buffer.from(payload["bundle.json"], "base64").toString("utf8"));
  const entries = new Map(bundleManifest.entries.map((entry) => [entry.path, entry.sha256]));

  for (const key of required) {
    if (key === "bundle.sig") {
      continue;
    }
    if (!entries.has(key)) {
      return { ok: false, reason: "bundle_manifest_missing_entry" };
    }
    const data = Buffer.from(payload[key], "base64");
    if (sha256(data) !== entries.get(key)) {
      return { ok: false, reason: "bundle_manifest_hash_mismatch" };
    }
  }

  const manifestBytes = Buffer.from(payload["manifest.json"], "base64");
  const manifestSig = Buffer.from(payload["signature.ed25519"], "base64");
  const sealBytes = Buffer.from(payload["seal.json"], "base64");
  const sealSig = Buffer.from(payload["seal.ed25519"], "base64");
  const publicKeyPem = Buffer.from(payload["public_key.ed25519"], "base64").toString("utf8");

  if (!verifyEd25519(Buffer.from(payload["bundle.json"], "base64"), Buffer.from(payload["bundle.sig"], "base64"), publicKeyPem)) {
    return { ok: false, reason: "bundle_manifest_invalid" };
  }
  if (!verifyEd25519(manifestBytes, manifestSig, publicKeyPem)) {
    return { ok: false, reason: "signature_invalid" };
  }
  if (!verifyEd25519(sealBytes, sealSig, publicKeyPem)) {
    return { ok: false, reason: "seal_invalid" };
  }

  return { ok: true, reason: null };
}

if (require.main === module) {
  const mediaPath = process.argv[2];
  if (!mediaPath) {
    console.error("Usage: node mkvVerifier.js <mkvPath>");
    process.exit(2);
  }
  const payloads = extractOriginPayloadsMkv(mediaPath);
  if (!payloads.length) {
    console.error("No Origin payload found");
    process.exit(2);
  }
  const result = validatePayload(payloads[0]);
  if (result.ok) {
    console.log("Origin payload verified");
    process.exit(0);
  }
  console.error(`Origin payload invalid: ${result.reason}`);
  process.exit(2);
}

module.exports = { extractOriginPayloadsMkv, validatePayload };
