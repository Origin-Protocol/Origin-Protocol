const fs = require("fs");
const crypto = require("crypto");

function sha256(buffer) {
  return crypto.createHash("sha256").update(buffer).digest("hex");
}

function verifyEd25519(data, signature, publicKeyPem) {
  return crypto.verify(null, data, publicKeyPem, signature);
}

function loadSidecar(path) {
  const raw = fs.readFileSync(path, "utf8");
  const parsed = JSON.parse(raw);
  return parsed.payload;
}

function b64ToBuffer(value) {
  return Buffer.from(value, "base64");
}

function verifySidecar(mediaPath, sidecarPath) {
  const payload = loadSidecar(sidecarPath);
  const bundleManifestBytes = b64ToBuffer(payload["bundle.json"]);
  const bundleSignature = b64ToBuffer(payload["bundle.sig"]);
  const manifestBytes = b64ToBuffer(payload["manifest.json"]);
  const manifestSignature = b64ToBuffer(payload["signature.ed25519"]);
  const sealBytes = b64ToBuffer(payload["seal.json"]);
  const sealSignature = b64ToBuffer(payload["seal.ed25519"]);
  const publicKeyPem = b64ToBuffer(payload["public_key.ed25519"]).toString("utf8");

  if (!verifyEd25519(bundleManifestBytes, bundleSignature, publicKeyPem)) {
    return { ok: false, reason: "bundle_manifest_invalid" };
  }

  const bundleManifest = JSON.parse(bundleManifestBytes.toString("utf8"));
  const entries = new Map(bundleManifest.entries.map((entry) => [entry.path, entry.sha256]));

  const expected = {
    "manifest.json": manifestBytes,
    "signature.ed25519": manifestSignature,
    "public_key.ed25519": Buffer.from(publicKeyPem, "utf8"),
    "seal.json": sealBytes,
    "seal.ed25519": sealSignature,
  };

  for (const [path, content] of Object.entries(expected)) {
    if (!entries.has(path)) {
      return { ok: false, reason: "bundle_contents_mismatch" };
    }
    if (sha256(content) !== entries.get(path)) {
      return { ok: false, reason: "bundle_hash_mismatch" };
    }
  }

  if (!verifyEd25519(manifestBytes, manifestSignature, publicKeyPem)) {
    return { ok: false, reason: "signature_invalid" };
  }
  if (!verifyEd25519(sealBytes, sealSignature, publicKeyPem)) {
    return { ok: false, reason: "seal_invalid" };
  }

  const manifest = JSON.parse(manifestBytes.toString("utf8"));
  const seal = JSON.parse(sealBytes.toString("utf8"));

  const mediaBytes = fs.readFileSync(mediaPath);
  const mediaHash = sha256(mediaBytes);
  if (mediaHash !== seal.content_hash) {
    return { ok: false, reason: "content_hash_mismatch" };
  }
  if (manifest.content_hash !== seal.content_hash) {
    return { ok: false, reason: "content_hash_mismatch" };
  }
  return { ok: true, reason: null };
}

if (require.main === module) {
  const mediaPath = process.argv[2];
  const sidecarPath = process.argv[3];
  if (!mediaPath || !sidecarPath) {
    console.error("Usage: node sidecarVerifier.js <mediaPath> <sidecarPath>");
    process.exit(2);
  }
  const result = verifySidecar(mediaPath, sidecarPath);
  if (result.ok) {
    console.log("Sidecar verified");
    process.exit(0);
  }
  console.error(`Sidecar verification failed: ${result.reason}`);
  process.exit(2);
}

module.exports = { verifySidecar };
