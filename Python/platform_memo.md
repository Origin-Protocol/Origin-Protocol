# Origin Protocol — Platform Adoption Memo

**Date:** January 18, 2026

## Executive summary
Origin Protocol provides a tamper‑evident, creator‑signed proof that stays attached to media across re‑uploads. Platforms can verify creator identity, asset IDs, and provenance to reduce piracy, strengthen attribution, and automate trust decisions in moderation and ranking pipelines.

This memo explains what has been delivered, how verification works end‑to‑end, why it matters, and what platforms must implement to adopt the policy. It also includes platform‑specific notes and checklists.

---

## What we accomplished (deliverables)

**Creator Companion app (desktop)**
- Seals videos and images with an Origin proof.
- Generates:
  - Sealed bundle: `*.origin.zip`
  - Sidecar proof: `*.origin.json`
- Verifies proofs locally.
- Simulates policy checks using profiles (Permissive / Standard / Strict).
- Supports provenance fields (source creator, source asset, relationship).
- Exports publish and compliance packs.
- Logs asset registry entries (creator ID, asset ID, file name/path, provenance).
- In‑app education for sidecars, attestations, registries, and revocation evidence.

**Policy and verification design**
- Key registry and revocation lists.
- Optional issuer attestations (enterprise trust).
- Platform matching (intended platforms).
- Reason codes for policy failures.

---

## Why it matters

- **Attribution that survives re‑uploads:** creator identity is cryptographically bound to the media.
- **Anti‑piracy enforcement:** untrusted or revoked keys can be blocked or sent to review.
- **Provenance and remix clarity:** provenance fields establish original source and relationship.
- **Automated trust decisions:** fast verification enables ranking, monetization, and moderation policies.
- **Compliance readiness:** clear artifacts and audit trails support legal and enterprise workflows.

---

## How it works (end‑to‑end)

### 1) Creator sealing
The creator app builds a manifest and signs it using the creator’s key pair. The manifest contains:
- `creator_id`
- `asset_id`
- `created_at`
- optional `intended_platforms`
- optional `media_metadata` (source creator, source asset, relationship)

Outputs:
- **Sealed bundle** (`*.origin.zip`) containing manifest + proof
- **Sidecar proof** (`*.origin.json`) stored next to the media

### 2) Platform verification
Platforms can verify either:
- **sealed bundle**, or
- **original media + sidecar JSON**

Verification steps:
1. Extract manifest + proof
2. Validate signature integrity
3. Validate key against registry
4. Ensure key is not revoked
5. Validate optional issuer attestation
6. Enforce optional intended‑platform matching

### 3) Enforcement outcomes
- **Pass:** show Origin badge, allow or prioritize distribution
- **Fail:** block, downrank, or send to review depending on profile

---

## Verification policy profiles

**Permissive**
- Signature integrity only

**Standard**
- Signature + key registry required

**Strict**
- Signature + key registry + revocation + attestation required

Platforms can map these profiles to moderation tiers (e.g., default uploads use Standard; verified creators use Strict).

---

## Blocking piracy and impersonation

**Asset ID verification**
- Confirm manifest `asset_id` exists in platform registry
- Mismatch or missing entry → unverified or blocked

**Creator verification**
- Confirm `creator_id` maps to a trusted key
- Key mismatch or revoked key → unverified or blocked

**Impersonation prevention**
- If a creator claims a known identity but uses an untrusted key, flag as impersonation

**Derivative content**
- If provenance is present, surface original creator and relationship
- If provenance is missing for derivative claims, flag for review

---

## Platform adoption checklist (shared)

1. **Proof ingestion**
   - Accept sidecar JSON or sealed bundle
   - Provide a verification service (inline or asynchronous)

2. **Trust infrastructure**
   - Maintain key registry for trusted creators
   - Maintain revocation list
   - Optional issuer attestations for enterprise workflows

3. **Policy enforcement**
   - Define which profile to apply per creator tier or content category
   - Decide pass/fail outcomes (badge, ranking, block, review)

4. **UI and UX**
   - Display “Origin Protected” badge on verified content
   - Provide verification failure reasons in moderation tools

5. **Analytics and reporting**
   - Log pass/fail rates
   - Track re‑uploads and origin collisions
   - Feed verification status into ranking/monetization

---

## Platform‑specific notes and checklists

### Meta / Instagram
**Checklist**
- Inline verification on upload
- Badge in post metadata
- Strict profile for verified creators

**Enforcement**
- Failures → integrity review
- Verified originals prioritized in ranking

### TikTok
**Checklist**
- Batch verification for high‑volume uploads
- Badge only for verified assets

**Enforcement**
- Unverified → reduced distribution
- Verified originals → creator boost

### YouTube
**Checklist**
- Verification at Content ID ingest
- Bind `asset_id` to Content ID claims

**Enforcement**
- Failures → copyright review
- Verified assets → auto‑confirm authorship

### X (Twitter)
**Checklist**
- Lightweight sidecar verification
- Badge in media info panel

**Enforcement**
- Unverified → reduced visibility
- Verified → higher trust in reports

### Reddit
**Checklist**
- Moderator tools show verification status

**Enforcement**
- Subreddits can require verified content for posting or flair

### Snapchat
**Checklist**
- Verify for Spotlight eligibility

**Enforcement**
- Unverified → remove from Spotlight
- Verified → badge + distribution boost

### Twitch
**Checklist**
- Verify VODs and clips post‑capture

**Enforcement**
- Verified originals get attribution in clip views

### Vimeo
**Checklist**
- Strict verification for Pro accounts

**Enforcement**
- Failures → upload warning or hold

### Pinterest
**Checklist**
- Verify images via sidecar

**Enforcement**
- Verified assets get source attribution

### LinkedIn
**Checklist**
- Enable verification for enterprise + creator programs

**Enforcement**
- Verified assets show trust badge on business posts

### DaVinci / Creator Tools
**Checklist**
- Integrate sealing into export workflow
- Default sidecar export for professional pipelines

---

## Implementation inputs needed from platforms

- Key registry format and distribution strategy
- Revocation list format and refresh interval
- Attestation issuer policy (optional)
- Verification service endpoint requirements
- UI placement for badges and failure reasons
- Ranking/moderation policy integration plan

---

## Recommended next steps

1. Platform selects an adoption profile (Permissive, Standard, Strict)
2. Platform aligns trust infrastructure (registry + revocation)
3. Integrate verification pipeline
4. Enable badges + moderation reasons
5. Pilot with verified creators and expand

---

## Implementation starter (platform verification)

Below is a minimal example using the Python SDK to verify a sealed bundle and apply a policy decision.

```python
from pathlib import Path

from origin_protocol.policy import VerificationPolicy
from origin_protocol.sdk import verify_sealed

policy = VerificationPolicy(
   require_seal=True,
   require_key_registry=True,
   require_revocation_check=True,
)

result = verify_sealed(Path("/uploads/asset.origin.zip"), policy)
if result.ok:
   decision = "allow_and_badge"
else:
   decision = "review_or_block"
   reasons = result.reasons
```

**Binary fingerprinting for piracy blocking** (platform‑side):
- On first verified upload, store `asset_id` and a binary or perceptual fingerprint.
- On every upload, compare fingerprints to prevent re‑uploads without sidecars.
- If a mismatch is found, block or route to dispute.


## Q&A

### 🔒 1. “Does Origin require us to change our upload pipeline?”
**Answer:** No. Origin is designed to be non‑disruptive.

Platforms do **not** need to:
- modify their transcoder
- preserve metadata
- change storage formats
- alter CDN behavior
- rewrite ingestion logic

Verification happens outside the media file. Platforms simply ingest a sidecar or sealed bundle and run a verification service.

### 🧩 2. “What if creators don’t use Origin? Does this break our platform?”
**Answer:** No. Origin is additive, not mandatory.

- Unsealed content continues to work normally.
- Verified content gets trust signals, ranking boosts, or monetization priority.
- Over time, creators adopt Origin because it benefits them, not because the platform forces it.

Origin is a progressive enhancement, not a requirement.

### 🧭 3. “What if someone steals a video and uploads it without the sidecar?”
**Answer:** This is the end‑goal protection path. Platforms can block protected content using **binary ingestion + asset‑ID fingerprinting**.

**Adoption flow**
1. **First verified upload** (with Origin proof):
   - Bind `asset_id → creator_id`
   - Bind `binary_fingerprint → asset_id`
2. **Every future upload**:
   - Compute the binary fingerprint (or perceptual near‑match)
   - Compare against your registry

**Enforcement**
- If a different user uploads the same asset (or near‑match), you can:
  - block it outright,
  - route it to a dispute flow, or
  - attribute it back to the original creator.

Origin supplies trusted authorship and asset IDs. **Your binary fingerprinting supplies zero‑tolerance theft prevention.**

**Implementation note**
- Origin does **not** provide a perceptual‑hashing engine.
- Platforms should use their existing fingerprinting or Content‑ID systems and link results to `asset_id`.

---

## Adoption reference code (Python)
Below is a minimal example showing how a platform can verify a sealed bundle with policy enforcement. This uses the existing SDK functions included in this repository.

```python
from pathlib import Path

from origin_protocol.policy import build_policy_for_profile
from origin_protocol.sdk import verify_sealed

# Inputs from your upload pipeline
bundle_path = Path("/ingest/origin/example.origin.zip")
platform_name = "Meta"

# Trust artifacts maintained by the platform
policy = build_policy_for_profile("strict")
policy = policy.__class__(
   **{
      **policy.__dict__,
      "platform": platform_name,
      "require_platform_match": True,
      "key_registry_path": Path("/trust/key_registry.json"),
      "require_key_registry": True,
      "revocation_list_path": Path("/trust/revocation_list.json"),
      "require_revocation_check": True,
      "attestation_path": Path("/trust/attestation.json"),
      "attestation_signature_path": Path("/trust/attestation.sig"),
      "trust_store_path": Path("/trust/issuer_keys.json"),
      "require_attestation": True,
   }
)

result = verify_sealed(bundle_path, policy)

if result.ok:
   # ✅ Verified — show badge, allow publish, or prioritize
   print("verified", result.reasons)
else:
   # ❌ Failed — block, downrank, or review
   print("failed", result.reasons, result.reason_details)
```

**Binary fingerprinting linkage (platform‑side):**
1. On first verified upload, store `asset_id → creator_id` and `binary_fingerprint → asset_id`.
2. On subsequent uploads, compute a binary/perceptual fingerprint and block or review on match.

### 🔍 4. “What if a creator loses their key?”
**Answer:** Origin supports:
- key rotation
- revocation
- re‑sealing
- enterprise attestations
Creators can recover identity through:
- platform‑verified identity
- enterprise attestation
- registry‑backed key replacement
This mirrors industry‑standard PKI practices.

### 🧬 5. “How do we know the creator is who they say they are?”
**Answer:** Origin separates identity from authorship.
Platforms can choose:
- self‑asserted creators (Standard profile)
- platform‑verified creators (Strict profile)
- enterprise‑verified creators (Attestation profile)
Origin gives platforms the flexibility to enforce identity at the level they choose.

### 🧠 6. “Does this slow down uploads?”
**Answer:** Verification is designed to be:
- lightweight
- parallelizable
- cacheable
- asynchronous‑friendly
Platforms can run verification:
- inline (fast creators)
- batch (high‑volume creators)
- post‑upload (Content ID‑style workflows)
Origin is intended for high‑volume creator platforms.

### 🧵 7. “What about derivative content? Remixes? Duets?”
**Answer:** Origin includes provenance fields:
- source creator
- source asset
- relationship type
Platforms can:
- enforce remix permissions
- surface lineage
- prevent impersonation
- auto‑attribute original creators
This is the first system that makes remix culture consensual and traceable.

### 🧱 8. “What if someone tries to impersonate a creator by generating their own key?”
**Answer:** If the platform enforces a key registry, impersonation attempts fail verification.
- The platform maintains a mapping of creator → key
- Impersonators fail registry checks
- Failures surface as “untrusted key” or “impersonation attempt”
Origin gives platforms cryptographic impersonation detection.

### 🗂️ 9. “Do we need to store the sealed bundle?”
**Answer:** No. Platforms only need to store:
- asset ID
- creator ID
- manifest hash
- verification result
The sealed bundle is a creator artifact, not a platform artifact.

### 🌍 10. “Is this compatible with C2PA?”
**Answer:** Yes — Origin is complementary, not competitive.
- C2PA is an in‑file metadata system
- Origin is an external cryptographic authorship system
Platforms can use both:
- C2PA for provenance
- Origin for authorship, identity, and enforcement
Origin proof is external and can survive transcoding; C2PA often does not.

### 🧱 11. “What’s the minimum we need to implement to get started?”
**Answer:** Three things:
- Accept sidecar or sealed bundle
- Run verification service
- Display badge + log results
Everything else (attestations, strict profiles, remix enforcement) is optional.

### 🧨 12. “What’s the risk if we don’t adopt Origin?”
**Answer:** You don’t say this directly — but the implication is clear:
- Creators will prefer platforms that protect them
- Brands will prefer platforms with authenticity guarantees
- Regulators will prefer systems with audit trails
- Competitors will adopt authenticity standards
Origin is becoming the default expectation for creator protection.

### 🧠 13. “What’s the business upside for us?”
**Answer:** Origin unlocks:
- safer feeds
- reduced piracy
- lower moderation costs
- higher creator trust
- better brand safety
- new monetization layers
- enterprise authenticity APIs
This is not a cost center — it’s a trust infrastructure investment.

### 🧭 14. “What’s the roadmap?”
**Answer:** Platforms want clarity. You give them:
- Q1: Verification service integration
- Q2: Badge + ranking integration
- Q3: Creator onboarding + registry alignment
- Q4: Remix permissions + enterprise attestations
This shows maturity and predictability.

🌟 If you want, I can turn this into:
- a polished PDF‑style Q&A appendix
- a platform‑facing FAQ
- a pitch deck slide set
- a “trust and safety” briefing
- a “creator partnerships” briefing
- a “legal and compliance” briefing
- a “technical integration guide”
- a “why Origin matters for your platform” one‑pager

---

## Reference implementation snippets (platform adoption)

These examples are intentionally minimal and show how to verify proofs, enforce policy, and bind asset IDs to fingerprints.

### 1) Verify a sealed bundle with policy (Python)
```python
from dataclasses import replace
from origin_protocol.policy import PolicyProfile, build_policy_for_profile, verify_sealed_bundle_with_policy

bundle_path = "./uploads/video.origin.zip"

# Start with a policy profile
policy = build_policy_for_profile(PolicyProfile.STANDARD)

# Optional evidence inputs (registry, revocation, attestation)
policy = replace(
   policy,
   key_registry_path="./trust/registry.json",
   revocation_list_path="./trust/revocation.json",
   require_key_registry=True,
   require_revocation_check=True,
)

result = verify_sealed_bundle_with_policy(bundle_path, policy)
if result.ok:
   print("verified")
else:
   print("rejected", result.reasons)
```

### 2) Verify a sidecar JSON (Python)
```python
from origin_protocol.container import validate_origin_payload

sidecar_path = "./uploads/video.mp4.origin.json"
payload = open(sidecar_path, "rb").read()
errors = validate_origin_payload(payload)

if errors:
   print("invalid", errors[0])
else:
   print("valid")
```

### 3) Bind asset IDs to fingerprints after first verified upload
```python
import hashlib

def fingerprint_file(path: str) -> str:
   data = open(path, "rb").read()
   return hashlib.sha256(data).hexdigest()

def register_verified_asset(asset_id: str, creator_id: str, media_path: str, registry_db) -> None:
   fp = fingerprint_file(media_path)
   registry_db["asset_by_fingerprint"][fp] = asset_id
   registry_db["creator_by_asset"][asset_id] = creator_id
```

### 4) Block re‑uploads using fingerprint match
```python
def enforce_reupload_policy(uploader_id: str, media_path: str, registry_db) -> str:
   fp = fingerprint_file(media_path)
   asset_id = registry_db["asset_by_fingerprint"].get(fp)
   if not asset_id:
      return "allow"
   owner = registry_db["creator_by_asset"].get(asset_id)
   if owner and owner != uploader_id:
      return "block_or_review"
   return "allow"
```

### 5) Example trust registry shape (JSON)
```json
{
  "creator-123": {
   "public_key": "<ed25519-public-key>",
   "key_id": "key-abc"
  }
}
```

### 6) Example revocation list shape (JSON)
```json
{
  "revoked_key_ids": ["key-abc", "key-def"],
  "updated_at": "2026-01-18T00:00:00Z"
}
```
