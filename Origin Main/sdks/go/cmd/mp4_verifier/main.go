// Command mp4_verifier validates Origin payloads embedded in MP4/MOV containers.
package main

import (
	"encoding/hex"
	"fmt"
	"os"

	"origin-protocol/validator"
)

func extractOriginPayloadsMp4(path string, originUUID string) [][]byte {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	uuidBytes, _ := hex.DecodeString(removeDashes(originUUID))
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

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: mp4_verifier <mp4Path>")
		os.Exit(2)
	}
	originUUID := validator.OriginUUID
	if override := os.Getenv("ORIGIN_UUID"); override != "" {
		originUUID = override
	}
	payloads := extractOriginPayloadsMp4(os.Args[1], originUUID)
	if len(payloads) == 0 {
		fmt.Println("No Origin payload found")
		os.Exit(2)
	}
	ok, reason := validator.ValidatePayload(payloads[0], os.Args[1], originUUID)
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
