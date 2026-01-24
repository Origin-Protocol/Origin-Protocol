// Command sealed_bundle_verifier validates Origin sealed bundles.
package main

import (
	"archive/zip"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"path"
	"strings"
	"time"
)

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

type sealPayload struct {
	CreatedAt    string `json:"created_at"`
	MediaPath    string `json:"media_path"`
	ManifestHash string `json:"manifest_hash"`
	ContentHash  string `json:"content_hash"`
}

type manifestPayload struct {
	CreatedAt   string `json:"created_at"`
	ContentHash string `json:"content_hash"`
	KeyID       string `json:"key_id"`
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
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

func verifyEd25519(data []byte, signature []byte, publicKey []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
}

func readZipFile(bundle *zip.Reader, name string) ([]byte, error) {
	for _, file := range bundle.File {
		if file.Name == name {
			reader, err := file.Open()
			if err != nil {
				return nil, err
			}
			defer reader.Close()
			return io.ReadAll(reader)
		}
	}
	return nil, fmt.Errorf("missing file")
}

func verifySealedBundle(bundlePath string) (bool, string) {
	reader, err := zip.OpenReader(bundlePath)
	if err != nil {
		return false, "bundle_read_error"
	}
	defer reader.Close()

	bundleManifestBytes, err := readZipFile(&reader.Reader, "bundle.json")
	if err != nil {
		return false, "bundle_manifest_invalid"
	}
	bundleSig, err := readZipFile(&reader.Reader, "bundle.sig")
	if err != nil {
		return false, "bundle_manifest_invalid"
	}
	manifestBytes, err := readZipFile(&reader.Reader, "manifest.json")
	if err != nil {
		return false, "manifest_invalid"
	}
	manifestSig, err := readZipFile(&reader.Reader, "signature.ed25519")
	if err != nil {
		return false, "signature_invalid"
	}
	sealBytes, err := readZipFile(&reader.Reader, "seal.json")
	if err != nil {
		return false, "seal_invalid"
	}
	sealSig, err := readZipFile(&reader.Reader, "seal.ed25519")
	if err != nil {
		return false, "seal_invalid"
	}
	publicKeyPem, err := readZipFile(&reader.Reader, "public_key.ed25519")
	if err != nil {
		return false, "public_key_invalid"
	}

	var manifest bundleManifest
	if err := json.Unmarshal(bundleManifestBytes, &manifest); err != nil {
		return false, "bundle_manifest_invalid"
	}
	if manifest.OriginSchema == "" || strings.ToLower(manifest.SignatureAlgorithm) != "ed25519" {
		return false, "bundle_manifest_invalid"
	}
	entries := make(map[string]string)
	for _, entry := range manifest.Entries {
		entries[entry.Path] = entry.Sha256
	}

	publicKey, err := parseEd25519PublicKey(publicKeyPem)
	if err != nil {
		return false, "public_key_invalid"
	}
	if !verifyEd25519(bundleManifestBytes, bundleSig, publicKey) {
		return false, "bundle_manifest_invalid"
	}

	expectedPaths := map[string]struct{}{}
	for _, entry := range manifest.Entries {
		expectedPaths[entry.Path] = struct{}{}
	}
	actualPaths := map[string]struct{}{}
	for _, file := range reader.File {
		if file.Name == "bundle.json" || file.Name == "bundle.sig" {
			continue
		}
		actualPaths[file.Name] = struct{}{}
	}
	if len(expectedPaths) != len(actualPaths) {
		return false, "bundle_contents_mismatch"
	}
	for pathKey := range expectedPaths {
		if _, ok := actualPaths[pathKey]; !ok {
			return false, "bundle_contents_mismatch"
		}
	}

	for _, entry := range manifest.Entries {
		content, err := readZipFile(&reader.Reader, entry.Path)
		if err != nil {
			return false, "bundle_hash_mismatch"
		}
		if sha256Hex(content) != entry.Sha256 {
			return false, "bundle_hash_mismatch"
		}
	}

	if !verifyEd25519(manifestBytes, manifestSig, publicKey) {
		return false, "signature_invalid"
	}
	if !verifyEd25519(sealBytes, sealSig, publicKey) {
		return false, "seal_invalid"
	}

	var manifestObj manifestPayload
	if err := json.Unmarshal(manifestBytes, &manifestObj); err != nil {
		return false, "manifest_invalid"
	}
	var sealObj sealPayload
	if err := json.Unmarshal(sealBytes, &sealObj); err != nil {
		return false, "seal_invalid"
	}

	manifestCreated, err := parseTimestamp(manifestObj.CreatedAt)
	if err != nil {
		return false, "manifest_invalid"
	}
	sealCreated, err := parseTimestamp(sealObj.CreatedAt)
	if err != nil {
		return false, "seal_invalid"
	}
	if sealCreated.Before(manifestCreated) {
		return false, "seal_timestamp_invalid"
	}
	if manifest.CreatedAt != "" {
		bundleCreatedAt, err := parseTimestamp(manifest.CreatedAt)
		if err == nil && bundleCreatedAt.Before(manifestCreated) {
			return false, "bundle_manifest_invalid"
		}
	}

	mediaPath := sealObj.MediaPath
	if mediaPath == "" {
		return false, "bundle_media_path_invalid"
	}
	normalized := path.Clean(mediaPath)
	if strings.HasPrefix(normalized, "/") || strings.HasPrefix(normalized, "..") || !strings.HasPrefix(normalized, "media/") {
		return false, "bundle_media_path_invalid"
	}
	if _, ok := entries[mediaPath]; !ok {
		return false, "bundle_media_missing"
	}

	mediaBytes, err := readZipFile(&reader.Reader, mediaPath)
	if err != nil {
		return false, "bundle_media_missing"
	}
	mediaHash := sha256Hex(mediaBytes)
	if mediaHash != sealObj.ContentHash {
		return false, "content_hash_mismatch"
	}
	manifestHash := sha256Hex(manifestBytes)
	if manifestHash != sealObj.ManifestHash {
		return false, "bundle_manifest_invalid"
	}
	if manifestObj.ContentHash != sealObj.ContentHash {
		return false, "content_hash_mismatch"
	}
	if manifest.ManifestHash != "" && manifest.ManifestHash != manifestHash {
		return false, "bundle_manifest_invalid"
	}
	if manifest.SealHash != "" && manifest.SealHash != sha256Hex(sealBytes) {
		return false, "bundle_manifest_invalid"
	}
	if manifest.MediaHash != "" && manifest.MediaHash != mediaHash {
		return false, "content_hash_mismatch"
	}
	if manifestObj.KeyID != "" {
		fingerprint := sha256Hex(publicKey)
		if manifestObj.KeyID != fingerprint {
			return false, "key_id_mismatch"
		}
	}

	return true, ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: sealed_bundle_verifier <bundlePath>")
		os.Exit(2)
	}
	ok, reason := verifySealedBundle(os.Args[1])
	if ok {
		fmt.Println("Sealed bundle verified")
		os.Exit(0)
	}
	fmt.Printf("Sealed bundle invalid: %s\n", reason)
	os.Exit(2)
}
