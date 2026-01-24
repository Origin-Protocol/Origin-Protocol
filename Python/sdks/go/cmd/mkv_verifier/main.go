// Command mkv_verifier validates Origin payloads embedded in MKV containers.
package main

import (
	"fmt"
	"os"
	"unicode/utf8"

	"origin-protocol/validator"
)

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
		if value < 0 || cursor+value > end {
			return result, fmt.Errorf("invalid element size")
		}
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
		payloads := [][]byte{}
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
						switch item[0] {
						case tagNameID:
							name = data[item[1] : item[1]+item[2]]
						case tagStringID:
							value = data[item[1] : item[1]+item[2]]
						}
					}
					if string(name) == "ORIGIN" && len(value) > 0 && utf8.Valid(value) {
						payloads = append(payloads, value)
					}
				}
			}
		}
		if len(payloads) > 0 {
			return payloads
		}
	}

	index := indexOf(data, []byte("ORIGIN"))
	if index == -1 {
		return nil
	}
	return scanForOriginTags(data)
}

func scanForOriginTags(data []byte) [][]byte {
	results := [][]byte{}
	nameMarker := []byte{0x45, 0xA3}
	valueMarker := []byte{0x44, 0x87}
	idx := 0
	for idx < len(data) {
		namePos := indexOf(data[idx:], append(nameMarker, []byte("ORIGIN")...))
		if namePos == -1 {
			break
		}
		namePos += idx
		valuePos := indexOf(data[namePos:], valueMarker)
		if valuePos == -1 {
			break
		}
		valuePos += namePos
		sizeStart := valuePos + len(valueMarker)
		if sizeStart >= len(data) {
			break
		}
		size, sizeLen, err := readVint(data, sizeStart)
		if err != nil {
			break
		}
		payloadStart := sizeStart + sizeLen
		payloadEnd := payloadStart + size
		if payloadEnd > len(data) {
			break
		}
		results = append(results, data[payloadStart:payloadEnd])
		idx = payloadEnd
	}
	return results
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("Usage: mkv_verifier <mkvPath>")
		os.Exit(2)
	}
	originUUID := validator.OriginUUID
	if override := os.Getenv("ORIGIN_UUID"); override != "" {
		originUUID = override
	}
	payloads := extractOriginPayloadsMkv(os.Args[1])
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
