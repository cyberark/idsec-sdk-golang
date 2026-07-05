package accounts

import (
	"io"
	"slices"
	"strings"
	"testing"
)

func TestParseAccountResponseNormalizesRemoteMachines(t *testing.T) {
	service := &IdsecPCloudAccountsService{}
	responseBody := io.NopCloser(strings.NewReader(`{
		"id": "account-1",
		"name": "test-account",
		"safe_name": "test-safe",
		"user_name": "test-user",
		"secret_management": {
			"automatic_management_enabled": true,
			"manual_management_reason": "manual",
			"last_modified_time": 123
		},
		"remote_machines_access": {
			"access_restricted_to_remote_machines": true,
			"remote_machines": "host1;host2"
		}
	}`))

	account, err := service.parseAccountResponse(responseBody)
	if err != nil {
		t.Fatalf("parseAccountResponse returned error: %v", err)
	}

	if account.AccountID != "account-1" {
		t.Fatalf("AccountID = %q, want %q", account.AccountID, "account-1")
	}
	if account.Username != "test-user" {
		t.Fatalf("Username = %q, want %q", account.Username, "test-user")
	}
	if !slices.Equal(account.RemoteMachines, []string{"host1", "host2"}) {
		t.Fatalf("RemoteMachines = %v, want %v", account.RemoteMachines, []string{"host1", "host2"})
	}
}

func TestParseAccountResponseInvalidTopLevel(t *testing.T) {
	service := &IdsecPCloudAccountsService{}
	responseBody := io.NopCloser(strings.NewReader(`[]`))

	if _, err := service.parseAccountResponse(responseBody); err == nil {
		t.Fatal("parseAccountResponse expected error")
	}
}

func TestNormalizeAccountItemMapInvalidNestedShapes(t *testing.T) {
	tests := []struct {
		name string
		data map[string]interface{}
	}{
		{
			name: "secret_management_not_object",
			data: map[string]interface{}{
				"secret_management": "invalid",
			},
		},
		{
			name: "remote_machines_access_not_object",
			data: map[string]interface{}{
				"remote_machines_access": "invalid",
			},
		},
		{
			name: "remote_machines_not_string",
			data: map[string]interface{}{
				"remote_machines_access": map[string]interface{}{
					"remote_machines": map[string]interface{}{},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := normalizeAccountItemMap(tt.data); err == nil {
				t.Fatal("normalizeAccountItemMap expected error")
			}
		})
	}
}
