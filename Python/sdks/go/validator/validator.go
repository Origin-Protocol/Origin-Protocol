// Package validator provides shared Origin payload verification helpers.
package validator

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"path"
	"strings"
	"time"
)

// OriginUUID is the UUID used for Origin payloads across container formats.
const OriginUUID = "e1b1c6b2-4d0a-4b40-9a1c-5d1d8f0e9c2a"

type bundleEntry struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

type bundleManifest struct {
	OriginSchema       string        `json:"origin_schema"`
	SignatureAlgorithm string        `json:"signature_algorithm"`
	CreatedAt          string        `json:"created_at"`
	ManifestHash       string        `json:"manifest_hash"`
	SealHash           string        `json:"seal_hash"`
	MediaHash          string        `json:"media_hash"`
	Entries            []bundleEntry `json:"entries"`
}

type originPayload struct {
	OriginSchema string            `json:"origin_schema"`
	OriginUUID   string            `json:"origin_uuid"`
	CreatedAt    string            `json:"created_at"`
	Nonce        string            `json:"nonce"`
	BundleHash   string            `json:"bundle_hash"`
	ManifestHash string            `json:"manifest_hash"`
	SealHash     string            `json:"seal_hash"`
	MediaHash    string            `json:"media_hash"`
	KeyID        string            `json:"key_id"`
	Payload      map[string]string `json:"payload"`
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

var signatureVerifiers = map[string]func([]byte, []byte, []byte) bool{
	"ed25519": verifyEd25519,
}

func verifyEd25519(data []byte, signature []byte, publicKey []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

func parseTimestamp(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, fmt.Errorf("missing timestamp")
	}
	if parsed, err := time.Parse(time.RFC3339Nano, value); err == nil {
		return parsed, nil
	}
	return time.Parse(time.RFC3339, value)
}

func isHex64(value string) bool {
	if len(value) != 64 {
		return false
	}
	for _, r := range strings.ToLower(value) {
		if (r < '0' || r > '9') && (r < 'a' || r > 'f') {
			return false
		}
	}
	return true
}

func parseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("invalid pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("not ed25519")
	}
	return key, nil
}

func normalizeSignatureAlgorithm(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

// ValidatePayload verifies a payload extracted from a container against the media file.
func ValidatePayload(payloadBytes []byte, mediaPath string, expectedOriginUUID string) (bool, string) {
	var payload originPayload
	if err := json.Unmarshal(payloadBytes, &payload); err != nil {
		return false, "payload_invalid_json"
	}
	if payload.OriginSchema == "" || payload.OriginUUID == "" || payload.CreatedAt == "" || payload.Nonce == "" {
		return false, "payload_missing_keys"
	}
	if payload.Payload == nil {
		return false, "payload_missing_keys"
	}
	if expectedOriginUUID != "" && payload.OriginUUID != expectedOriginUUID {
		return false, "container_payload_mismatch"
	}
	if _, err := parseTimestamp(payload.CreatedAt); err != nil {
		return false, "container_payload_invalid"
	}
	if payload.BundleHash != "" && !isHex64(payload.BundleHash) {
		return false, "container_payload_invalid"
	}
	if payload.ManifestHash != "" && !isHex64(payload.ManifestHash) {
		return false, "container_payload_invalid"
	}
	if payload.SealHash != "" && !isHex64(payload.SealHash) {
		return false, "container_payload_invalid"
	}
	if payload.MediaHash != "" && !isHex64(payload.MediaHash) {
		return false, "container_payload_invalid"
	}
	if payload.KeyID != "" && !isHex64(payload.KeyID) {
		return false, "key_id_mismatch"
	}

	required := []string{
		"bundle.json",
		"bundle.sig",
		"manifest.json",
		"signature.ed25519",
		"seal.json",
		"seal.ed25519",
		"public_key.ed25519",
	}
	for _, key := range required {
		if _, ok := payload.Payload[key]; !ok {
			return false, "payload_missing_keys"
		}
	}

	bundleManifestBytes, _ := base64.StdEncoding.DecodeString(payload.Payload["bundle.json"])
	var manifest bundleManifest
	if err := json.Unmarshal(bundleManifestBytes, &manifest); err != nil {
		return false, "bundle_manifest_invalid"
	}
	algorithm := normalizeSignatureAlgorithm(manifest.SignatureAlgorithm)
	if algorithm == "" {
		algorithm = "ed25519"
	}
	verifier, ok := signatureVerifiers[algorithm]
	if manifest.OriginSchema == "" || !ok {
		return false, "bundle_manifest_invalid"
	}
	entries := make(map[string]string)
	for _, entry := range manifest.Entries {
		entries[entry.Path] = entry.Sha256
	}

	entryRequired := []string{
		"manifest.json",
		"signature.ed25519",
		"seal.json",
		"seal.ed25519",
		"public_key.ed25519",
	}
	for _, key := range entryRequired {
		value := payload.Payload[key]
		data, _ := base64.StdEncoding.DecodeString(value)
		if entries[key] == "" {
			return false, "bundle_manifest_missing_entry"
		}
		if sha256Hex(data) != entries[key] {
			return false, "bundle_manifest_hash_mismatch"
		}
	}

	manifestBytes, _ := base64.StdEncoding.DecodeString(payload.Payload["manifest.json"])
	manifestSig, _ := base64.StdEncoding.DecodeString(payload.Payload["signature.ed25519"])
	sealBytes, _ := base64.StdEncoding.DecodeString(payload.Payload["seal.json"])
	sealSig, _ := base64.StdEncoding.DecodeString(payload.Payload["seal.ed25519"])
	publicKeyPem, _ := base64.StdEncoding.DecodeString(payload.Payload["public_key.ed25519"])

	publicKey, err := parseEd25519PublicKey(publicKeyPem)
	if err != nil {
		return false, "public_key_invalid"
	}

	bundleSig, _ := base64.StdEncoding.DecodeString(payload.Payload["bundle.sig"])
	if !verifier(bundleManifestBytes, bundleSig, publicKey) {
		return false, "bundle_manifest_invalid"
	}
	if !verifier(manifestBytes, manifestSig, publicKey) {
		return false, "signature_invalid"
	}
	if !verifier(sealBytes, sealSig, publicKey) {
		return false, "seal_invalid"
	}

	var manifestObj map[string]any
	if err := json.Unmarshal(manifestBytes, &manifestObj); err != nil {
		return false, "manifest_invalid"
	}
	var sealObj map[string]any
	if err := json.Unmarshal(sealBytes, &sealObj); err != nil {
		return false, "seal_invalid"
	}

	manifestCreated, err := parseTimestamp(manifestObj["created_at"].(string))
	if err != nil {
		return false, "manifest_invalid"
	}
	sealCreated, err := parseTimestamp(sealObj["created_at"].(string))
	if err != nil {
		return false, "seal_invalid"
	}
	if sealCreated.Before(manifestCreated) {
		return false, "seal_timestamp_invalid"
	}
	if manifest.CreatedAt != "" {
		bundleCreatedAt, err := parseTimestamp(manifest.CreatedAt)
		if err == nil && bundleCreatedAt.Before(sealCreated) {
			return false, "bundle_manifest_invalid"
		}
	}

	sealHash, ok := sealObj["content_hash"].(string)
	if !ok {
		return false, "seal_invalid"
	}

	mediaPathValue, ok := sealObj["media_path"].(string)
	if !ok || mediaPathValue == "" {
		return false, "bundle_media_path_invalid"
	}
	normalized := path.Clean(mediaPathValue)
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "..") || !strings.HasPrefix(normalized, "media/") {
		return false, "bundle_media_path_invalid"
	}
	if _, ok := entries[mediaPathValue]; !ok {
		return false, "bundle_media_missing"
	}

	mediaHash := sealHash

	manifestContentHash, ok := manifestObj["content_hash"].(string)
	if !ok || manifestContentHash != sealHash {
		return false, "content_hash_mismatch"
	}

	if payload.ManifestHash != "" && payload.ManifestHash != sha256Hex(manifestBytes) {
		return false, "container_payload_mismatch"
	}
	if payload.SealHash != "" && payload.SealHash != sha256Hex(sealBytes) {
		return false, "container_payload_mismatch"
	}
	if payload.MediaHash != "" && payload.MediaHash != mediaHash {
		return false, "content_hash_mismatch"
	}
	if payload.KeyID != "" {
		fingerprint := sha256Hex(publicKey)
		if payload.KeyID != fingerprint {
			return false, "key_id_mismatch"
		}
	}

	if manifest.ManifestHash != "" && manifest.ManifestHash != sha256Hex(manifestBytes) {
		return false, "bundle_manifest_invalid"
	}
	if manifest.SealHash != "" && manifest.SealHash != sha256Hex(sealBytes) {
		return false, "bundle_manifest_invalid"
	}
	if manifest.MediaHash != "" && manifest.MediaHash != mediaHash {
		return false, "content_hash_mismatch"
	}

	if intended, ok := manifestObj["intended_platforms"]; ok {
		if platforms, ok := intended.([]any); ok {
			for _, item := range platforms {
				if _, ok := item.(string); !ok {
					return false, "manifest_invalid"
				}
			}
		} else {
			return false, "manifest_invalid"
		}
	}

	return true, ""
}
