package maxproto

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
)

const (
	okcallsSDKVersion   = "0.3.1.2"
	okcallsClientAppKey = "CGPGAGLGDIHBABABA"
	okcallsCapabilities = "1877f"
)

func BuildInternalParams(deviceID string) string {
	m := map[string]any{
		"platform":           "ANDROID",
		"sdkVersion":         okcallsSDKVersion,
		"protocolVersion":    5,
		"onlyAdminCanRecord": false,
		"waitForAdmin":       false,
		"capabilities":       okcallsCapabilities,
		"clientAppKey":       okcallsClientAppKey,
		"deviceId":           deviceID,
	}
	data, _ := json.Marshal(m)
	return string(data)
}

type ICEServers struct {
	URLs       []string `json:"urls"`
	Username   string   `json:"username,omitempty"`
	Credential string   `json:"credential,omitempty"`
}

type CallInfo struct {
	Endpoint      string     `json:"endpoint"`
	WtEndpoint    string     `json:"wtEndpoint"`
	WsIPAddresses []string   `json:"wsIpAddresses,omitempty"`
	WtIPAddresses []string   `json:"wtIpAddresses,omitempty"`
	Turn          ICEServers `json:"turn"`
	Stun          ICEServers `json:"stun"`
	ID            struct {
		Internal any `json:"internal"`
		External any `json:"external"`
	} `json:"id"`
	PeerID     any            `json:"peerId"`
	ClientType string         `json:"clientType"`
	DeviceIdx  any            `json:"deviceIdx"`
	Raw        map[string]any `json:"-"`
}

func (c *Client) ResolveUID(ctx context.Context, phone string) (int64, error) {
	resp, err := c.Cmd(ctx, 46, map[string]any{"phone": phone})
	if err != nil {
		return 0, err
	}
	m, ok := resp.(map[string]any)
	if !ok {
		return 0, fmt.Errorf("unexpected ResolveUID response type: %T", resp)
	}
	contact, ok := m["contact"].(map[string]any)
	if !ok {
		return 0, errors.New("contact field not found in response")
	}
	idVal, ok := contact["id"]
	if !ok {
		return 0, errors.New("id field not found in contact")
	}

	id, ok := toInt64(idVal)
	if !ok {
		return 0, fmt.Errorf("unexpected type for contact id: %T", idVal)
	}

	if id == 0 {
		return 0, errors.New("contact id is 0 or invalid")
	}
	return id, nil
}

// toInt64 normalises any integer-ish value the msgpack decoder can produce.
// Widths vary with how the server encoded the number (and ExtType payloads are
// re-decoded independently), so every signed/unsigned width is accepted.
func toInt64(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), true
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), true
	case float32:
		return int64(n), true
	case float64:
		return int64(n), true
	}
	return 0, false
}

func (c *Client) VideoChatStart(ctx context.Context, calleeIDs []int64, conversationID string) (map[string]any, error) {
	if conversationID == "" {
		conversationID = uuid.NewString()
	}
	payload := map[string]any{
		"conversationId": conversationID,
		"calleeIds":      calleeIDs,
		"isVideo":        true,
	}
	resp, err := c.Cmd(ctx, 76, payload)
	if err != nil {
		return nil, err
	}
	m, ok := resp.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected VideoChatStart response type: %T", resp)
	}
	return m, nil
}

func (c *Client) VideoChatJoin(ctx context.Context, joinLink, internalParams, conversationID string) (map[string]any, error) {
	payload := map[string]any{
		"joinLink":       joinLink,
		"internalParams": internalParams,
		"isVideo":        true,
	}
	if conversationID != "" {
		payload["conversationId"] = conversationID
	}
	resp, err := c.Cmd(ctx, 166, payload)
	if err != nil {
		return nil, err
	}
	m, ok := resp.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("unexpected VideoChatJoin response type: %T", resp)
	}
	return m, nil
}

func ParseCallInfo(joinResp map[string]any) (*CallInfo, error) {
	if joinResp == nil {
		return nil, errors.New("joinResp is nil")
	}

	ipVal, ok := joinResp["internalParams"]
	if !ok {
		return nil, errors.New("missing internalParams in join response")
	}

	var data []byte
	var err error

	switch v := ipVal.(type) {
	case string:
		data = []byte(v)
	case map[string]any:
		data, err = json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal internalParams map: %w", err)
		}
	default:
		data, err = json.Marshal(v)
		if err != nil {
			return nil, fmt.Errorf("unexpected internalParams type %T: %w", ipVal, err)
		}
	}

	// UseNumber so the participant ids (id.internal is a 16-digit integer, and
	// the same value ws2 addresses participants by) keep their exact digits.
	// A plain decode makes them float64, and fmt.Sprint of that renders
	// scientific notation ("1.125...e+15"), which never matches the id ws2
	// sends — that mismatch breaks self/peer identification during signaling.
	var ci CallInfo
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&ci); err != nil {
		return nil, fmt.Errorf("failed to unmarshal CallInfo: %w", err)
	}

	var raw map[string]any
	rawDec := json.NewDecoder(bytes.NewReader(data))
	rawDec.UseNumber()
	if err := rawDec.Decode(&raw); err == nil {
		ci.Raw = raw
	}

	return &ci, nil
}
