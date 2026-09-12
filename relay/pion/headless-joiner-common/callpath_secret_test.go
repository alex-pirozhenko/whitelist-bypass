package joiner

import (
	"bytes"
	"encoding/base64"
	"testing"

	"github.com/alex-pirozhenko/whitelist-bypass/relay/tunnel"
)

func TestCallpathTunnelSecret(t *testing.T) {
	joinLink := "https://example.com/join/roomToken123"
	expectedDerivedSecret := tunnel.DeriveSecretFromJoinLink(joinLink)

	// Case 1: callpathTunnelSecret("", joinRef, false) returns the derived secret, no error
	t.Run("FallbackAllowed", func(t *testing.T) {
		secret, err := callpathTunnelSecret("", joinLink, false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(secret, expectedDerivedSecret) {
			t.Errorf("expected secret %s, got %s", expectedDerivedSecret, secret)
		}
	})

	// Case 2: callpathTunnelSecret("", joinRef, true) returns an error (required, none given)
	t.Run("FallbackDenied", func(t *testing.T) {
		_, err := callpathTunnelSecret("", joinLink, true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := "callpath: tunnelSecret is required (RequireTunnelSecret=true) but none was provided"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

	// Case 3: callpathTunnelSecret(base64OfAnything16BytesOrMore, "irrelevant", false) returns decoded bytes, no error, regardless of joinRef
	t.Run("ValidExplicitSecret", func(t *testing.T) {
		rawSecret := []byte("this is a very secure secret 16 bytes") // 37 bytes
		b64Secret := base64.StdEncoding.EncodeToString(rawSecret)

		secret, err := callpathTunnelSecret(b64Secret, "irrelevant", false)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !bytes.Equal(secret, rawSecret) {
			t.Errorf("expected secret %s, got %s", rawSecret, secret)
		}
	})

	// Case 4: callpathTunnelSecret(base64Of8Bytes, "irrelevant", false) returns an error (too short) even though required is false
	t.Run("ExplicitSecretTooShort", func(t *testing.T) {
		rawSecret := []byte("short") // 5 bytes
		b64Secret := base64.StdEncoding.EncodeToString(rawSecret)

		_, err := callpathTunnelSecret(b64Secret, "irrelevant", false)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := "callpath: tunnelSecret is invalid or shorter than 16 bytes"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

	// Case 5: callpathTunnelSecret("not-valid-base64!!!", "irrelevant", true) returns invalid secret error rather than required error
	t.Run("ExplicitSecretInvalidBase64", func(t *testing.T) {
		_, err := callpathTunnelSecret("not-valid-base64!!!", "irrelevant", true)
		if err == nil {
			t.Fatal("expected error, got nil")
		}
		expectedErr := "callpath: tunnelSecret is invalid or shorter than 16 bytes"
		if err.Error() != expectedErr {
			t.Errorf("expected error %q, got %q", expectedErr, err.Error())
		}
	})

	// Case 6: Cryptographic proof of different secrets exchanging nothing readable
	t.Run("DifferingSecretsCryptographicProof", func(t *testing.T) {
		secretA := []byte("secret A 16 bytes long")
		secretB := []byte("secret B 16 bytes long")

		b64SecretA := base64.StdEncoding.EncodeToString(secretA)
		b64SecretB := base64.StdEncoding.EncodeToString(secretB)

		secA, err := callpathTunnelSecret(b64SecretA, "irrelevant", false)
		if err != nil {
			t.Fatalf("secret A error: %v", err)
		}
		secB, err := callpathTunnelSecret(b64SecretB, "irrelevant", false)
		if err != nil {
			t.Fatalf("secret B error: %v", err)
		}

		obfA, err := tunnel.NewTunnelObfuscator(secA)
		if err != nil {
			t.Fatalf("obfuscator A error: %v", err)
		}
		obfB, err := tunnel.NewTunnelObfuscator(secB)
		if err != nil {
			t.Fatalf("obfuscator B error: %v", err)
		}

		payload := []byte("confidential business payload data")

		// 6a. Test with EncodeDataKeyframe (keyframe)
		keyframeEncA := obfA.EncodeDataKeyframe(payload)
		resKeyframeB := obfB.Decode(keyframeEncA)

		if bytes.Equal(resKeyframeB.Payload, payload) {
			t.Errorf("cryptographic failure: Obfuscator B decrypted Obfuscator A's keyframe payload!")
		}
		if len(resKeyframeB.Payload) != 0 {
			t.Errorf("expected decrypted payload to be empty on decrypt failure, got: %q", resKeyframeB.Payload)
		}
		if !resKeyframeB.HasFrame {
			t.Errorf("expected HasFrame to be true for keyframe header even on decrypt failure")
		}
		if !resKeyframeB.Keepalive {
			t.Errorf("expected Keepalive to be true for keyframe header decrypt failure fallback")
		}

		// 6b. Test with EncodeData (interframe)
		interframeEncA := obfA.EncodeData(payload)
		resInterframeB := obfB.Decode(interframeEncA)

		if bytes.Equal(resInterframeB.Payload, payload) {
			t.Errorf("cryptographic failure: Obfuscator B decrypted Obfuscator A's interframe payload!")
		}
		if len(resInterframeB.Payload) != 0 {
			t.Errorf("expected decrypted payload to be empty on decrypt failure, got: %q", resInterframeB.Payload)
		}
		if resInterframeB.HasFrame {
			t.Errorf("expected HasFrame to be false for interframe header decrypt failure")
		}
	})
}
