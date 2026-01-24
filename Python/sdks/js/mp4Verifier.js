const fs = require("fs");
const crypto = require("crypto");

const ORIGIN_UUID = "e1b1c6b2-4d0a-4b40-9a1c-5d1d8f0e9c2a";

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function verifyEd25519(data, signature, publicKeyPem) {
  return crypto.verify(null, data, publicKeyPem, signature);
}

function readBoxes(buffer) {
  let offset = 0;
  const boxes = [];
  while (offset + 8 <= buffer.length) {
    let size = buffer.readUInt32BE(offset);
    const type = buffer.slice(offset + 4, offset + 8).toString("ascii");
    let headerSize = 8;
    if (size === 1) {
      size = Number(buffer.readBigUInt64BE(offset + 8));
      headerSize = 16;
    } else if (size === 0) {
      size = buffer.length - offset;
    }
    const payloadStart = offset + headerSize;
    const payloadEnd = offset + size;
    if (payloadEnd > buffer.length) {
      break;
    }
    boxes.push({ type, payload: buffer.slice(payloadStart, payloadEnd) });
    if (size === 0) {
      break;
    }
    offset = payloadEnd;
  }
  return boxes;
}

function extractOriginPayloadsMp4(filePath) {
  const data = fs.readFileSync(filePath);
  const boxes = readBoxes(data);
  const uuidBytes = Buffer.from(ORIGIN_UUID.replace(/-/g, ""), "hex");
  const payloads = [];
  for (const box of boxes) {
    if (box.type !== "uuid") {
      continue;
    }
    if (box.payload.length < 16) {
      continue;
    }
    if (box.payload.subarray(0, 16).equals(uuidBytes)) {
      payloads.push(box.payload.subarray(16));
    }
  }
  return payloads;
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
    console.error("Usage: node mp4Verifier.js <mp4Path>");
    process.exit(2);
  }
  const payloads = extractOriginPayloadsMp4(mediaPath);
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

module.exports = { extractOriginPayloadsMp4, validatePayload };
