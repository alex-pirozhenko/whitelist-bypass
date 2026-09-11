package maxproto

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
)

func TestEncodeMsgRoundTripAndHeader(t *testing.T) {
	payload := map[string]any{
		"userAgent": AndroidUA,
		"deviceId":  "test-device-id",
	}

	data, err := encodeMsg(0, 0, 6, payload)
	if err != nil {
		t.Fatalf("encodeMsg failed: %v", err)
	}

	if len(data) < 10 {
		t.Fatalf("encoded data too short: %d", len(data))
	}

	// Assert the exact 10-byte header bytes for (cmd=0,seq=0,op=6,len=N):
	// 0a 00 00 00 00 06 00 <len24>
	expectedHeaderStart := []byte{0x0a, 0x00, 0x00, 0x00, 0x00, 0x06, 0x00}
	if !bytes.Equal(data[0:7], expectedHeaderStart) {
		t.Errorf("header mismatch: got %x, expected %x", data[0:7], expectedHeaderStart)
	}

	// Round-trip decode
	cmd, seq, opcode, decodedPayload, err := decodeMsg(data)
	if err != nil {
		t.Fatalf("decodeMsg failed: %v", err)
	}

	if cmd != 0 {
		t.Errorf("cmd mismatch: got %d, expected 0", cmd)
	}
	if seq != 0 {
		t.Errorf("seq mismatch: got %d, expected 0", seq)
	}
	if opcode != 6 {
		t.Errorf("opcode mismatch: got %d, expected 6", opcode)
	}

	decodedMap, ok := decodedPayload.(map[string]any)
	if !ok {
		t.Fatalf("decoded payload is not a map: %T", decodedPayload)
	}

	if decodedMap["deviceId"] != "test-device-id" {
		t.Errorf("deviceId mismatch: got %v, expected test-device-id", decodedMap["deviceId"])
	}
}

func TestDecodeMsgWithCompression(t *testing.T) {
	// Construct a highly-compressible repetitive payload to guarantee lz4 compression
	repeatStr := string(bytes.Repeat([]byte("A"), 1000))
	srcPayload := map[string]any{
		"data": repeatStr,
	}

	uncompressed, err := msgpack.Marshal(srcPayload)
	if err != nil {
		t.Fatalf("failed to marshal uncompressed payload: %v", err)
	}

	// Compress
	compBuf := make([]byte, lz4.CompressBlockBound(len(uncompressed)))
	compLen, err := lz4.CompressBlock(uncompressed, compBuf, nil)
	if err != nil {
		t.Fatalf("CompressBlock failed: %v", err)
	}
	if compLen == 0 {
		t.Fatalf("CompressBlock returned 0 (not compressed)")
	}

	compressed := compBuf[:compLen]

	// Calculate compression ratio/byte B such that B * len(compressed) >= len(uncompressed)
	uLen := len(uncompressed)
	cLen := len(compressed)
	B := byte((uLen + cLen - 1) / cLen)

	// Build the mock framed message with compression Byte B
	header := make([]byte, 10)
	header[0] = protoVersion
	header[1] = 1                                // cmd (response)
	binary.BigEndian.PutUint16(header[2:4], 42)  // seq
	binary.BigEndian.PutUint16(header[4:6], 100) // opcode
	header[6] = B
	header[7] = byte((cLen >> 16) & 0xFF)
	header[8] = byte((cLen >> 8) & 0xFF)
	header[9] = byte(cLen & 0xFF)

	frameData := append(header, compressed...)

	// Decode and verify
	cmd, seq, opcode, decodedPayload, err := decodeMsg(frameData)
	if err != nil {
		t.Fatalf("decodeMsg failed: %v", err)
	}

	if cmd != 1 {
		t.Errorf("cmd mismatch: got %d, expected 1", cmd)
	}
	if seq != 42 {
		t.Errorf("seq mismatch: got %d, expected 42", seq)
	}
	if opcode != 100 {
		t.Errorf("opcode mismatch: got %d, expected 100", opcode)
	}

	decodedMap, ok := decodedPayload.(map[string]any)
	if !ok {
		t.Fatalf("decoded payload is not a map: %T", decodedPayload)
	}

	if decodedMap["data"] != repeatStr {
		t.Errorf("decompressed content mismatch")
	}
}

func TestDeepDecode(t *testing.T) {
	// Construct msgpack ExtType code=1 value
	nestedBytes, err := msgpack.Marshal(int64(12345))
	if err != nil {
		t.Fatalf("failed to marshal nested integer: %v", err)
	}

	ext := Ext{
		Type: 1,
		Data: nestedBytes,
	}

	input := map[any]any{
		"outer": []any{
			ext,
			map[any]any{
				"nested": &ext,
			},
		},
	}

	decoded := deepDecode(input)

	decodedMap, ok := decoded.(map[string]any)
	if !ok {
		t.Fatalf("deepDecode did not convert map[any]any to map[string]any: %T", decoded)
	}

	outerSlice, ok := decodedMap["outer"].([]any)
	if !ok {
		t.Fatalf("outer is not a slice: %T", decodedMap["outer"])
	}

	val1, ok := outerSlice[0].(int64)
	if !ok || val1 != 12345 {
		t.Errorf("failed to decode ext value in slice: got %v (%T), expected 12345 (int64)", outerSlice[0], outerSlice[0])
	}

	nestedMap, ok := outerSlice[1].(map[string]any)
	if !ok {
		t.Fatalf("nested map is not map[string]any: %T", outerSlice[1])
	}

	val2, ok := nestedMap["nested"].(int64)
	if !ok || val2 != 12345 {
		t.Errorf("failed to decode ext value in nested map: got %v (%T), expected 12345 (int64)", nestedMap["nested"], nestedMap["nested"])
	}
}

func TestBuildInternalParams(t *testing.T) {
	s := BuildInternalParams("my-device-id")

	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		t.Fatalf("failed to unmarshal BuildInternalParams JSON: %v", err)
	}

	if len(m) != 8 {
		t.Errorf("expected 8 fields, got %d: %v", len(m), m)
	}

	expected := map[string]any{
		"platform":           "ANDROID",
		"sdkVersion":         "0.3.1.2",
		"protocolVersion":    float64(5),
		"onlyAdminCanRecord": false,
		"waitForAdmin":       false,
		"capabilities":       "1877f",
		"clientAppKey":       "CGPGAGLGDIHBABABA",
		"deviceId":           "my-device-id",
	}

	for k, v := range expected {
		if m[k] != v {
			t.Errorf("field %s mismatch: got %v, expected %v", k, m[k], v)
		}
	}
}
