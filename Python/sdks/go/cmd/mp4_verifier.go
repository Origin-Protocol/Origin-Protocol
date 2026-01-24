//go:build ignore
// +build ignore

// Command mp4_verifier validates Origin payloads embedded in MP4/MOV containers.
package main

import (
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

const defaultOriginUUID = "e1b1c6b2-4d0a-4b40-9a1c-5d1d8f0e9c2a"

func resolveOriginUUID() string {
	if override := os.Getenv("ORIGIN_UUID"); override != "" {
		return override
	}
	return defaultOriginUUID
}

type bundleEntry struct {
	Path   string `json:"path"`
	Sha256 string `json:"sha256"`
}

type bundleManifest struct {
	Entries []bundleEntry `json:"entries"`
}

func sha256Hex(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}

func verifyEd25519(data []byte, signature []byte, publicKey []byte) bool {
	return ed25519.Verify(publicKey, data, signature)
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

func extractOriginPayloadsMp4(path string) [][]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	uuidBytes, _ := hex.DecodeString(removeDashes(resolveOriginUUID()))
	payloads := [][]byte{}
	for offset := 0; offset+8 <= len(data); {
		size := int(readUint32(data[offset : offset+4]))
		typeBytes := data[offset+4 : offset+8]
		header := 8
		if size == 1 {
			if offset+16 > len(data) {
				break
			}
			size = int(readUint64(data[offset+8 : offset+16]))
			header = 16
		} else if size == 0 {
			size = len(data) - offset
		}
		if offset+size > len(data) {
			break
		}
		if string(typeBytes) == "uuid" {
			payload := data[offset+header : offset+size]
			if len(payload) >= 16 && equalBytes(payload[:16], uuidBytes) {
				payloads = append(payloads, payload[16:])
			}
		}
		if size == 0 {
			break
		}
		offset += size
	}
	return payloads
}

func validatePayload(payloadBytes []byte) (bool, string) {
	var payloadJSON map[string]any
	if err := json.Unmarshal(payloadBytes, &payloadJSON); err != nil {
		return false, "payload_invalid_json"
	}
	payload, ok := payloadJSON["payload"].(map[string]any)
	if !ok {
		return false, "payload_missing_keys"
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
		if _, ok := payload[key]; !ok {
			return false, "payload_missing_keys"
		}
	}

	bundleManifestBytes, _ := base64.StdEncoding.DecodeString(payload["bundle.json"].(string))
	var manifest bundleManifest
	if err := json.Unmarshal(bundleManifestBytes, &manifest); err != nil {
		return false, "bundle_manifest_invalid"
	}
	entries := make(map[string]string)
	for _, entry := range manifest.Entries {
		entries[entry.Path] = entry.Sha256
	}

	for _, key := range required {
		if key == "bundle.sig" {
			continue
		}
		value, _ := payload[key].(string)
		data, _ := base64.StdEncoding.DecodeString(value)
		if entries[key] == "" {
			return false, "bundle_manifest_missing_entry"
		}
		if sha256Hex(data) != entries[key] {
			return false, "bundle_manifest_hash_mismatch"
		}
	}

	manifestBytes, _ := base64.StdEncoding.DecodeString(payload["manifest.json"].(string))
	manifestSig, _ := base64.StdEncoding.DecodeString(payload["signature.ed25519"].(string))
	sealBytes, _ := base64.StdEncoding.DecodeString(payload["seal.json"].(string))
	sealSig, _ := base64.StdEncoding.DecodeString(payload["seal.ed25519"].(string))
	publicKeyPem, _ := base64.StdEncoding.DecodeString(payload["public_key.ed25519"].(string))

	publicKey, err := parseEd25519PublicKey(publicKeyPem)
	if err != nil {
		return false, "public_key_invalid"
	}

	bundleSig, _ := base64.StdEncoding.DecodeString(payload["bundle.sig"].(string))
	if !verifyEd25519(bundleManifestBytes, bundleSig, publicKey) {
		return false, "bundle_manifest_invalid"
	}
	if !verifyEd25519(manifestBytes, manifestSig, publicKey) {
		return false, "signature_invalid"
	}
	if !verifyEd25519(sealBytes, sealSig, publicKey) {
		return false, "seal_invalid"
	}

	return true, ""
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: mp4_verifier <mp4Path>")
		os.Exit(2)
	}
	payloads := extractOriginPayloadsMp4(os.Args[1])
	if len(payloads) == 0 {
		fmt.Println("No Origin payload found")
		os.Exit(2)
	}
	ok, reason := validatePayload(payloads[0])
	if ok {
		fmt.Println("Origin payload verified")
		os.Exit(0)
	}
	fmt.Printf("Origin payload invalid: %s\n", reason)
	os.Exit(2)
}

func removeDashes(value string) string {
	result := make([]rune, 0, len(value))
	for _, r := range value {
		if r != '-' {
			result = append(result, r)
		}
	}
	return string(result)
}

func readUint32(data []byte) uint32 {
	return uint32(data[0])<<24 | uint32(data[1])<<16 | uint32(data[2])<<8 | uint32(data[3])
}

func readUint64(data []byte) uint64 {
	return uint64(data[0])<<56 | uint64(data[1])<<48 | uint64(data[2])<<40 | uint64(data[3])<<32 |
		uint64(data[4])<<24 | uint64(data[5])<<16 | uint64(data[6])<<8 | uint64(data[7])
}

func equalBytes(a []byte, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := 0; i < len(a); i++ {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
