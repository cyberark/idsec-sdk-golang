package k8s

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
)

// makeUnsignedJWT builds a valid 3-segment JWT with an "alg=none" header and the
// supplied claims. Signature is empty. Used solely for ParseUnverified-based tests.
func makeUnsignedJWT(t *testing.T, claims map[string]interface{}) string {
	t.Helper()
	header := map[string]string{"alg": "none", "typ": "JWT"}
	hdrBytes, err := json.Marshal(header)
	if err != nil {
		t.Fatalf("marshal header: %v", err)
	}
	payloadBytes, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("marshal claims: %v", err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(hdrBytes) + "." + enc.EncodeToString(payloadBytes) + "."
}

func TestExtractInternalSessionID(t *testing.T) {
	t.Parallel()

	validToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": "sid-abc-123",
		"tenant_id":           "tenant-xyz",
	})
	missingClaimToken := makeUnsignedJWT(t, map[string]interface{}{
		"tenant_id": "tenant-xyz",
	})
	emptyClaimToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": "   ",
	})
	nonStringClaimToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": 12345,
	})

	tests := []struct {
		name      string
		token     string
		want      string
		wantErr   bool
		errSubstr string
	}{
		{name: "valid_token_returns_sid", token: validToken, want: "sid-abc-123"},
		{name: "empty_token_errors", token: "", wantErr: true, errSubstr: "is empty"},
		{name: "whitespace_token_errors", token: "   ", wantErr: true, errSubstr: "is empty"},
		{name: "garbage_token_errors", token: "not.a.jwt", wantErr: true, errSubstr: "failed to parse"},
		{name: "missing_claim_errors", token: missingClaimToken, wantErr: true, errSubstr: "missing"},
		{name: "empty_claim_errors", token: emptyClaimToken, wantErr: true, errSubstr: "is empty"},
		{name: "non_string_claim_errors", token: nonStringClaimToken, wantErr: true, errSubstr: "not a string"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExtractInternalSessionID(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (sid=%q)", got)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tt.want {
				t.Fatalf("got %q, want %q", got, tt.want)
			}
		})
	}
}
