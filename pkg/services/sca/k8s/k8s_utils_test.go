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

func TestParseNamespaceName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name        string
		namespaceID string
		want        string
	}{
		{name: "empty", namespaceID: "", want: ""},
		{name: "whitespace_only", namespaceID: "   ", want: ""},
		{name: "bare_name_unchanged", namespaceID: "remediation-tracker", want: "remediation-tracker"},
		{name: "bare_name_trimmed", namespaceID: "  ns-prod  ", want: "ns-prod"},
		{
			name:        "no_marker_returns_input_unchanged",
			namespaceID: "/subscriptions/x/managedClusters/c/some-other-path",
			want:        "/subscriptions/x/managedClusters/c/some-other-path",
		},
		{
			name:        "full_azure_resource_id",
			namespaceID: "/subscriptions/541038cf-0e42-47c0-ace1-f3263530fd72/resourcegroups/roie-resource-group/providers/Microsoft.ContainerService/managedClusters/prod-vulnerability-scanner/namespaces/remediation-tracker",
			want:        "remediation-tracker",
		},
		{
			name:        "trailing_slash_after_namespace",
			namespaceID: "/subscriptions/x/managedClusters/c/namespaces/remediation-tracker/",
			want:        "remediation-tracker/",
		},
		{
			name:        "extra_segments_after_namespace",
			namespaceID: "/subscriptions/x/managedClusters/c/namespaces/remediation-tracker/pods/foo",
			want:        "remediation-tracker/pods/foo",
		},
		{
			name:        "marker_case_sensitive_no_match_returns_input",
			namespaceID: "/subscriptions/x/managedClusters/c/Namespaces/remediation-tracker",
			want:        "/subscriptions/x/managedClusters/c/Namespaces/remediation-tracker",
		},
		{
			name:        "preserves_namespace_casing",
			namespaceID: "/subscriptions/x/managedClusters/c/namespaces/My-Namespace",
			want:        "My-Namespace",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := ParseNamespaceName(tt.namespaceID); got != tt.want {
				t.Fatalf("ParseNamespaceName(%q) = %q, want %q", tt.namespaceID, got, tt.want)
			}
		})
	}
}

func TestExtractISPSessionClaims(t *testing.T) {
	t.Parallel()

	bothClaimsToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": "sid-abc-123",
		"user_uuid":           "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
		"tenant_id":           "tenant-xyz",
	})
	sessionOnlyToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": "sid-abc-123",
	})
	uuidOnlyToken := makeUnsignedJWT(t, map[string]interface{}{
		"user_uuid": "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
	})
	neitherClaimToken := makeUnsignedJWT(t, map[string]interface{}{
		"tenant_id": "tenant-xyz",
	})
	nonStringSessionToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": 12345,
		"user_uuid":           "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
	})
	nonStringUUIDToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": "sid-abc-123",
		"user_uuid":           []string{"not", "a", "string"},
	})
	whitespaceClaimsToken := makeUnsignedJWT(t, map[string]interface{}{
		"internal_session_id": "  sid-trimmed  ",
		"user_uuid":           "  91ff5db2-24c9-4a2b-b414-ec416dfbd43f  ",
	})

	tests := []struct {
		name      string
		token     string
		wantSID   string
		wantUUID  string
		wantErr   bool
		errSubstr string
	}{
		{
			name:     "both_claims_present",
			token:    bothClaimsToken,
			wantSID:  "sid-abc-123",
			wantUUID: "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
		},
		{
			name:     "session_id_only_uuid_empty",
			token:    sessionOnlyToken,
			wantSID:  "sid-abc-123",
			wantUUID: "",
		},
		{
			name:     "user_uuid_only_session_empty",
			token:    uuidOnlyToken,
			wantSID:  "",
			wantUUID: "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
		},
		{
			name:     "neither_claim_both_empty_no_error",
			token:    neitherClaimToken,
			wantSID:  "",
			wantUUID: "",
		},
		{
			name:     "non_string_session_id_treated_as_empty",
			token:    nonStringSessionToken,
			wantSID:  "",
			wantUUID: "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
		},
		{
			name:     "non_string_user_uuid_treated_as_empty",
			token:    nonStringUUIDToken,
			wantSID:  "sid-abc-123",
			wantUUID: "",
		},
		{
			name:     "whitespace_claims_are_trimmed",
			token:    whitespaceClaimsToken,
			wantSID:  "sid-trimmed",
			wantUUID: "91ff5db2-24c9-4a2b-b414-ec416dfbd43f",
		},
		{name: "empty_token_errors", token: "", wantErr: true, errSubstr: "is empty"},
		{name: "whitespace_token_errors", token: "   ", wantErr: true, errSubstr: "is empty"},
		{name: "malformed_token_errors", token: "not.a.jwt", wantErr: true, errSubstr: "failed to parse"},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := ExtractISPSessionClaims(tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil (claims=%+v)", got)
				}
				if tt.errSubstr != "" && !strings.Contains(err.Error(), tt.errSubstr) {
					t.Fatalf("error %q does not contain %q", err.Error(), tt.errSubstr)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.SessionID != tt.wantSID {
				t.Errorf("SessionID = %q, want %q", got.SessionID, tt.wantSID)
			}
			if got.UserUUID != tt.wantUUID {
				t.Errorf("UserUUID = %q, want %q", got.UserUUID, tt.wantUUID)
			}
		})
	}
}
