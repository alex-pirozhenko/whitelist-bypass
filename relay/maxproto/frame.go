package maxproto

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/pierrec/lz4/v4"
	"github.com/vmihailenco/msgpack/v5"
)

const protoVersion = 10

// unpackPayload decodes a raw msgpack blob into a generic tree. The MAX server
// emits maps with non-string keys (e.g. integer-keyed config maps), which the
// default vmihailenco decoder rejects when targeting map[string]any — the
// Python client tolerates them via strict_map_key=False. Decoding every map as
// an untyped map[any]any matches that behaviour; deepDecode then normalises the
// tree back to map[string]any and resolves ExtType(code=1) integers.
func unpackPayload(raw []byte) (any, error) {
	dec := msgpack.NewDecoder(bytes.NewReader(raw))
	dec.SetMapDecoder(func(d *msgpack.Decoder) (any, error) {
		return d.DecodeUntypedMap()
	})
	var v any
	if err := dec.Decode(&v); err != nil {
		return nil, err
	}
	return v, nil
}

type Ext struct {
	Type int8
	Data []byte
}

func (e *Ext) MarshalMsgpack() ([]byte, error) {
	return e.Data, nil
}

func (e *Ext) UnmarshalMsgpack(b []byte) error {
	e.Type = 1
	e.Data = make([]byte, len(b))
	copy(e.Data, b)
	return nil
}

func init() {
	msgpack.RegisterExt(1, &Ext{Type: 1})
}

func encodeMsg(cmd byte, seq uint16, opcode uint16, payload any) ([]byte, error) {
	var body []byte
	if payload != nil {
		var err error
		body, err = msgpack.Marshal(payload)
		if err != nil {
			return nil, fmt.Errorf("failed to msgpack marshal payload: %w", err)
		}
	}

	header := make([]byte, 10)
	header[0] = protoVersion
	header[1] = cmd
	binary.BigEndian.PutUint16(header[2:4], seq)
	binary.BigEndian.PutUint16(header[4:6], opcode)
	header[6] = 0 // Compression byte is always 0 for outbound

	bodyLen := len(body)
	if bodyLen > 0xFFFFFF {
		return nil, fmt.Errorf("payload length %d exceeds 24-bit max", bodyLen)
	}
	header[7] = byte((bodyLen >> 16) & 0xFF)
	header[8] = byte((bodyLen >> 8) & 0xFF)
	header[9] = byte(bodyLen & 0xFF)

	return append(header, body...), nil
}

func decodeMsg(data []byte) (cmd byte, seq uint16, opcode uint16, payload any, err error) {
	if len(data) < 10 {
		return 0, 0, 0, nil, fmt.Errorf("message too short (%d bytes)", len(data))
	}
	if data[0] != protoVersion {
		return 0, 0, 0, nil, fmt.Errorf("invalid proto version: %d", data[0])
	}
	cmd = data[1]
	seq = binary.BigEndian.Uint16(data[2:4])
	opcode = binary.BigEndian.Uint16(data[4:6])
	compression := data[6]
	payloadLen := (int(data[7]) << 16) | (int(data[8]) << 8) | int(data[9])

	if len(data) < 10+payloadLen {
		return 0, 0, 0, nil, fmt.Errorf("message payload truncated: got %d bytes, need %d", len(data)-10, payloadLen)
	}

	if payloadLen > 0 {
		raw := data[10 : 10+payloadLen]
		if compression > 0 {
			uncompressedSize := int(payloadLen) * int(compression)
			dst := make([]byte, uncompressedSize)
			n, err := lz4.UncompressBlock(raw, dst)
			if err != nil {
				return 0, 0, 0, nil, fmt.Errorf("lz4 decompression failed: %w", err)
			}
			raw = dst[:n]
		}
		unpacked, uerr := unpackPayload(raw)
		if uerr != nil {
			return 0, 0, 0, nil, fmt.Errorf("msgpack unmarshal failed: %w", uerr)
		}
		payload = deepDecode(unpacked)
	}

	return cmd, seq, opcode, payload, nil
}

func deepDecode(v any) any {
	if v == nil {
		return nil
	}

	switch val := v.(type) {
	case Ext:
		if val.Type == 1 {
			var nested any
			if err := msgpack.Unmarshal(val.Data, &nested); err == nil {
				return deepDecode(nested)
			}
		}
	case *Ext:
		if val != nil && val.Type == 1 {
			var nested any
			if err := msgpack.Unmarshal(val.Data, &nested); err == nil {
				return deepDecode(nested)
			}
		}
	case map[string]any:
		m := make(map[string]any, len(val))
		for k, valV := range val {
			m[k] = deepDecode(valV)
		}
		return m
	case map[any]any:
		m := make(map[string]any, len(val))
		for k, valV := range val {
			kStr := fmt.Sprintf("%v", deepDecode(k))
			m[kStr] = deepDecode(valV)
		}
		return m
	case []any:
		s := make([]any, len(val))
		for i, valV := range val {
			s[i] = deepDecode(valV)
		}
		return s
	}
	return v
}
