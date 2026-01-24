//go:build ignore
// +build ignore

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

func readVint(data []byte, offset int) (int, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("invalid vint")
	}
	first := data[offset]
	mask := byte(0x80)
	length := 1
	for length <= 8 && (first&mask) == 0 {
		mask >>= 1
		length++
	}
	if length > 8 {
		return 0, 0, fmt.Errorf("invalid vint")
	}
	value := int(first & (mask - 1))
	for i := 1; i < length; i++ {
		if offset+i >= len(data) {
			return 0, 0, fmt.Errorf("invalid vint")
		}
		value = (value << 8) | int(data[offset+i])
	}
	return value, length, nil
}

func readElementID(data []byte, offset int) (int, int, error) {
	if offset >= len(data) {
		return 0, 0, fmt.Errorf("invalid id")
	}
	first := data[offset]
	mask := byte(0x80)
	length := 1
	for length <= 4 && (first&mask) == 0 {
		mask >>= 1
		length++
	}
	if length > 4 {
		return 0, 0, fmt.Errorf("invalid id")
	}
	value := 0
	for i := 0; i < length; i++ {
		value = (value << 8) | int(data[offset+i])
	}
	return value, length, nil
}

func iterElements(data []byte, offset int, size int) ([][3]int, error) {
	end := offset + size
	cursor := offset
	result := [][3]int{}
	for cursor < end {
		id, idLen, err := readElementID(data, cursor)
		if err != nil {
			return result, err
		}
		cursor += idLen
		value, sizeLen, err := readVint(data, cursor)
		if err != nil {
			return result, err
		}
		cursor += sizeLen
		result = append(result, [3]int{id, cursor, value})
		cursor += value
	}
	return result, nil
}

func extractOriginPayloadsMkv(path string) [][]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	const (
		tagsID      = 0x1254c367
		tagID       = 0x7373
		simpleTagID = 0x67c8
		tagNameID   = 0x45a3
		tagStringID = 0x4487
	)

	elements, err := iterElements(data, 0, len(data))
	if err == nil {
		for _, element := range elements {
			if element[0] != tagsID {
				continue
			}
			tags, err := iterElements(data, element[1], element[2])
			if err != nil {
				continue
			}
			for _, tag := range tags {
				if tag[0] != tagID {
					continue
				}
				simpleTags, err := iterElements(data, tag[1], tag[2])
				if err != nil {
					continue
				}
				for _, simple := range simpleTags {
					if simple[0] != simpleTagID {
						continue
					}
					var name []byte
					var value []byte
					items, err := iterElements(data, simple[1], simple[2])
					if err != nil {
						continue
					}
					for _, item := range items {
						if item[0] == tagNameID {
							name = data[item[1] : item[1]+item[2]]
						} else if item[0] == tagStringID {
							value = data[item[1] : item[1]+item[2]]
						}
					}
					if string(name) == "ORIGIN" && len(value) > 0 {
						return [][]byte{value}
					}
				}
			}
		}
	}

	index := indexOf(data, []byte("ORIGIN"))
	if index == -1 {
		return nil
	}
	return [][]byte{data[index+6:]}
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
		fmt.Println("Usage: mkv_verifier <mkvPath>")
		os.Exit(2)
	}
	payloads := extractOriginPayloadsMkv(os.Args[1])
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

func indexOf(data []byte, search []byte) int {
	for i := 0; i+len(search) <= len(data); i++ {
		match := true
		for j := 0; j < len(search); j++ {
			if data[i+j] != search[j] {
				match = false
				break
			}
		}
		if match {
			return i
		}
	}
	return -1
}
