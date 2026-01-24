package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path"
	"strings"
	"time"
)

type sidecarFile struct {
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

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
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

func readSidecar(path string) (sidecarFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return sidecarFile{}, err
	}
	var sc sidecarFile
	if err := json.Unmarshal(content, &sc); err != nil {
		return sidecarFile{}, err
	}
	return sc, nil
}

func decodePayload(payload map[string]string, key string) ([]byte, error) {
	value, ok := payload[key]
	if !ok {
		return nil, errors.New("missing payload key")
	}
	return base64.StdEncoding.DecodeString(value)
}

func verifySidecar(mediaPath string, sidecarPath string) (bool, string) {
	sc, err := readSidecar(sidecarPath)
	if err != nil {
		return false, "sidecar_read_error"
	}
	if sc.OriginSchema == "" || sc.OriginUUID == "" || sc.CreatedAt == "" || sc.Nonce == "" {
		return false, "container_payload_invalid"
	}

	bundleManifestBytes, err := decodePayload(sc.Payload, "bundle.json")
	if err != nil {
		return false, "bundle_manifest_missing"
	}
	bundleSig, err := decodePayload(sc.Payload, "bundle.sig")
	if err != nil {
		return false, "bundle_signature_missing"
	}
	manifestBytes, _ := decodePayload(sc.Payload, "manifest.json")
	manifestSig, _ := decodePayload(sc.Payload, "signature.ed25519")
	sealBytes, _ := decodePayload(sc.Payload, "seal.json")
	sealSig, _ := decodePayload(sc.Payload, "seal.ed25519")
	publicKeyPem, _ := decodePayload(sc.Payload, "public_key.ed25519")

	publicKey, err := parseEd25519PublicKey(publicKeyPem)
	if err != nil {
		return false, "public_key_invalid"
	}

	if !verifyEd25519(bundleManifestBytes, bundleSig, publicKey) {
		return false, "bundle_manifest_invalid"
	}

	var manifest bundleManifest
	if err := json.Unmarshal(bundleManifestBytes, &manifest); err != nil {
		return false, "bundle_manifest_invalid"
	}
	if manifest.OriginSchema == "" || manifest.SignatureAlgorithm == "" {
		return false, "bundle_manifest_invalid"
	}
	if manifest.SignatureAlgorithm != "ed25519" {
		return false, "bundle_manifest_invalid"
	}
	if manifest.ManifestHash == "" || manifest.SealHash == "" || manifest.MediaHash == "" {
		return false, "bundle_manifest_invalid"
	}
	entries := make(map[string]string, len(manifest.Entries))
	for _, entry := range manifest.Entries {
		entries[entry.Path] = entry.Sha256
	}

	expected := map[string][]byte{
		"manifest.json":      manifestBytes,
		"signature.ed25519":  manifestSig,
		"public_key.ed25519": publicKeyPem,
		"seal.json":          sealBytes,
		"seal.ed25519":       sealSig,
	}

	for path, content := range expected {
		hash, ok := entries[path]
		if !ok {
			return false, "bundle_contents_mismatch"
		}
		if sha256Hex(content) != hash {
			return false, "bundle_hash_mismatch"
		}
	}

	if !verifyEd25519(manifestBytes, manifestSig, publicKey) {
		return false, "signature_invalid"
	}
	if !verifyEd25519(sealBytes, sealSig, publicKey) {
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

	createdAt, err := parseTimestamp(manifestObj["created_at"].(string))
	if err != nil {
		return false, "manifest_invalid"
	}
	sealCreatedAt, err := parseTimestamp(sealObj["created_at"].(string))
	if err != nil {
		return false, "seal_invalid"
	}
	if sealCreatedAt.Before(createdAt) {
		return false, "seal_timestamp_invalid"
	}
	if manifest.CreatedAt != "" {
		bundleCreatedAt, err := parseTimestamp(manifest.CreatedAt)
		if err == nil && bundleCreatedAt.Before(createdAt) {
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

	mediaBytes, err := os.ReadFile(mediaPath)
	if err != nil {
		return false, "media_read_error"
	}
	mediaHash := sha256Hex(mediaBytes)
	if mediaHash != sealHash {
		return false, "content_hash_mismatch"
	}

	manifestHashValue, ok := manifestObj["content_hash"].(string)
	if !ok || manifestHashValue != sealHash {
		return false, "content_hash_mismatch"
	}

	if sc.ManifestHash != "" {
		if sha256Hex(manifestBytes) != sc.ManifestHash {
			return false, "container_payload_mismatch"
		}
	}
	if sc.SealHash != "" {
		if sha256Hex(sealBytes) != sc.SealHash {
			return false, "container_payload_mismatch"
		}
	}
	if sc.MediaHash != "" {
		if sc.MediaHash != mediaHash {
			return false, "content_hash_mismatch"
		}
	}
	if sc.KeyID != "" {
		if !isHex64(sc.KeyID) {
			return false, "key_id_mismatch"
		}
		fingerprint := sha256Hex(publicKey)
		if sc.KeyID != fingerprint {
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

func main() {
	if len(os.Args) < 3 {
		fmt.Println("Usage: sidecar_verifier <mediaPath> <sidecarPath>")
		os.Exit(2)
	}
	ok, reason := verifySidecar(os.Args[1], os.Args[2])
	if ok {
		fmt.Println("Sidecar verified")
		os.Exit(0)
	}
	fmt.Printf("Sidecar verification failed: %s\n", reason)
	os.Exit(2)
}

func parseEd25519PublicKey(pemBytes []byte) (ed25519.PublicKey, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("invalid pem")
	}
	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("not ed25519")
	}
	return key, nil
}
