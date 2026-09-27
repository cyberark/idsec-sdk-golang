package accounts

import (
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
)

// sortOperationsByPath returns operations sorted by their "path" value, so assertions do not
// encode the incidental order buildUpdateOperations happens to emit them in.
func sortOperationsByPath(operations []map[string]interface{}) []map[string]interface{} {
	sorted := make([]map[string]interface{}, len(operations))
	copy(sorted, operations)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i]["path"].(string) < sorted[j]["path"].(string)
	})
	return sorted
}

func operationPaths(operations []map[string]interface{}) []string {
	paths := make([]string, len(operations))
	for i, operation := range operations {
		paths[i] = operation["path"].(string)
	}
	sort.Strings(paths)
	return paths
}

func TestBuildUpdateOperations_AllNilProducesZeroOperations(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 0 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 0: %v", len(operations), operations)
	}
}

func TestBuildUpdateOperations_OnlyAddress(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		Address:   common.Ptr("10.0.0.1"),
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 1 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 1: %v", len(operations), operations)
	}
	if operations[0]["path"] != "/address" {
		t.Errorf("path = %v, want %q", operations[0]["path"], "/address")
	}
	if operations[0]["value"] != "10.0.0.1" {
		t.Errorf("value = %v, want %q", operations[0]["value"], "10.0.0.1")
	}
}

// TestBuildUpdateOperations_ManualManagementReasonWithoutAutomaticManagement is the
// anti-regression test for the gate-flattening described in design doc §6.2. Before this
// refactor, ManualManagementReason was only emitted when AutomaticManagementEnabled was also
// supplied, silently dropping a practitioner's change whenever they touched the reason alone. If
// someone re-nests the gates in buildUpdateOperations, this test must be what fails.
func TestBuildUpdateOperations_ManualManagementReasonWithoutAutomaticManagement(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		IdsecPCloudUpdateAccountSecretManagement: accountsmodels.IdsecPCloudUpdateAccountSecretManagement{
			ManualManagementReason: common.Ptr("no longer auto-managed"),
		},
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 1 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 1: %v", len(operations), operations)
	}
	if operations[0]["path"] != "/secretManagement/manualManagementReason" {
		t.Errorf("path = %v, want %q", operations[0]["path"], "/secretManagement/manualManagementReason")
	}
	if operations[0]["value"] != "no longer auto-managed" {
		t.Errorf("value = %v, want %q", operations[0]["value"], "no longer auto-managed")
	}
}

// TestBuildUpdateOperations_AccessRestrictedToRemoteMachinesFalseIsSent proves the old truthiness
// gate (`if updateAccount.AccessRestrictedToRemoteMachines`) is gone: false is a real, distinct
// value now that the field is a pointer, and it must reach the PATCH body rather than being
// silently omitted.
func TestBuildUpdateOperations_AccessRestrictedToRemoteMachinesFalseIsSent(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		IdsecPCloudUpdateAccountRemoteMachinesAccess: accountsmodels.IdsecPCloudUpdateAccountRemoteMachinesAccess{
			AccessRestrictedToRemoteMachines: common.Ptr(false),
		},
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 1 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 1: %v", len(operations), operations)
	}
	if operations[0]["path"] != "/remoteMachinesAccess/accessRestrictedToRemoteMachines" {
		t.Errorf("path = %v, want %q", operations[0]["path"], "/remoteMachinesAccess/accessRestrictedToRemoteMachines")
	}
	if operations[0]["value"] != false {
		t.Errorf("value = %v, want %v (not omitted)", operations[0]["value"], false)
	}
}

func TestBuildUpdateOperations_OnlyRemoteMachines(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		IdsecPCloudUpdateAccountRemoteMachinesAccess: accountsmodels.IdsecPCloudUpdateAccountRemoteMachinesAccess{
			RemoteMachines: []string{"host1", "host2"},
		},
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 1 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 1: %v", len(operations), operations)
	}
	if operations[0]["path"] != "/remoteMachinesAccess/remoteMachines" {
		t.Errorf("path = %v, want %q", operations[0]["path"], "/remoteMachinesAccess/remoteMachines")
	}
	if operations[0]["value"] != "host1;host2" {
		t.Errorf("value = %v, want %q", operations[0]["value"], "host1;host2")
	}
}

// TestBuildUpdateOperations_PlatformAccountPropertiesLowerCamelCasesInnerKeys pins the
// common.ConvertToCamelCase equivalence: buildUpdateOperations must lower-camel-case the inner
// keys of the properties map the same way SerializeJSONCamel used to.
func TestBuildUpdateOperations_PlatformAccountPropertiesLowerCamelCasesInnerKeys(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		PlatformAccountProperties: map[string]interface{}{
			"logon_domain": "example.com",
			"port_number":  "22",
		},
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 1 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 1: %v", len(operations), operations)
	}
	if operations[0]["path"] != "/platformAccountProperties" {
		t.Errorf("path = %v, want %q", operations[0]["path"], "/platformAccountProperties")
	}
	value, ok := operations[0]["value"].(map[string]interface{})
	if !ok {
		t.Fatalf("value = %#v, want map[string]interface{}", operations[0]["value"])
	}
	want := map[string]interface{}{
		"logonDomain": "example.com",
		"portNumber":  "22",
	}
	if len(value) != len(want) {
		t.Fatalf("value = %#v, want %#v", value, want)
	}
	for key, wantValue := range want {
		if value[key] != wantValue {
			t.Errorf("value[%q] = %v, want %v", key, value[key], wantValue)
		}
	}
}

// TestBuildUpdateOperations_NameEmptyStringIsSent documents the new explicit-clear semantics:
// Name = &"" is a caller-supplied empty string, distinct from nil ("not supplied"), and must be
// sent rather than dropped by omitempty as it would have been with the old plain-string field.
func TestBuildUpdateOperations_NameEmptyStringIsSent(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID: "account-1",
		Name:      common.Ptr(""),
	}

	operations := buildUpdateOperations(updateAccount)

	if len(operations) != 1 {
		t.Fatalf("buildUpdateOperations() = %d operations, want 1: %v", len(operations), operations)
	}
	if operations[0]["path"] != "/name" {
		t.Errorf("path = %v, want %q", operations[0]["path"], "/name")
	}
	if operations[0]["value"] != "" {
		t.Errorf("value = %v, want empty string", operations[0]["value"])
	}
}

// TestBuildUpdateOperations_GoldenFullPayload is the golden test over a fully populated struct.
// Operations are compared order-insensitively (sorted by path) since buildUpdateOperations does
// not guarantee -- and callers must not depend on -- a particular emission order.
func TestBuildUpdateOperations_GoldenFullPayload(t *testing.T) {
	updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
		AccountID:  "account-1",
		Secret:     common.Ptr("hunter2"),
		SecretFile: common.Ptr("/tmp/secret"),
		Name:       common.Ptr("full-account"),
		Address:    common.Ptr("10.0.0.1"),
		Username:   common.Ptr("svc-user"),
		PlatformID: common.Ptr("UnixSSH"),
		PlatformAccountProperties: map[string]interface{}{
			"logon_domain": "example.com",
		},
		IdsecPCloudUpdateAccountSecretManagement: accountsmodels.IdsecPCloudUpdateAccountSecretManagement{
			AutomaticManagementEnabled: common.Ptr(true),
			ManualManagementReason:     common.Ptr("reason"),
		},
		IdsecPCloudUpdateAccountRemoteMachinesAccess: accountsmodels.IdsecPCloudUpdateAccountRemoteMachinesAccess{
			RemoteMachines:                   []string{"host1", "host2"},
			AccessRestrictedToRemoteMachines: common.Ptr(true),
		},
	}

	operations := buildUpdateOperations(updateAccount)

	// Secret and SecretFile are handled by resolveUpdateSecret / UpdateCredentialsInVault, not by
	// buildUpdateOperations, so they must not appear as PATCH operations.
	wantPaths := []string{
		"/name",
		"/address",
		"/username",
		"/platformId",
		"/platformAccountProperties",
		"/secretManagement/automaticManagementEnabled",
		"/secretManagement/manualManagementReason",
		"/remoteMachinesAccess/remoteMachines",
		"/remoteMachinesAccess/accessRestrictedToRemoteMachines",
	}
	sort.Strings(wantPaths)

	gotPaths := operationPaths(operations)
	if len(gotPaths) != len(wantPaths) {
		t.Fatalf("buildUpdateOperations() paths = %v, want %v", gotPaths, wantPaths)
	}
	for i := range wantPaths {
		if gotPaths[i] != wantPaths[i] {
			t.Errorf("buildUpdateOperations() paths = %v, want %v", gotPaths, wantPaths)
			break
		}
	}

	wantValues := map[string]interface{}{
		"/name":                      "full-account",
		"/address":                   "10.0.0.1",
		"/username":                  "svc-user",
		"/platformId":                "UnixSSH",
		"/platformAccountProperties": map[string]interface{}{"logonDomain": "example.com"},
		"/secretManagement/automaticManagementEnabled":           true,
		"/secretManagement/manualManagementReason":               "reason",
		"/remoteMachinesAccess/remoteMachines":                   "host1;host2",
		"/remoteMachinesAccess/accessRestrictedToRemoteMachines": true,
	}
	for _, operation := range sortOperationsByPath(operations) {
		path := operation["path"].(string)
		want, ok := wantValues[path]
		if !ok {
			t.Errorf("unexpected operation path %q", path)
			continue
		}
		if properties, ok := want.(map[string]interface{}); ok {
			gotProperties, ok := operation["value"].(map[string]interface{})
			if !ok {
				t.Errorf("value for %q = %#v, want map[string]interface{}", path, operation["value"])
				continue
			}
			for key, wantValue := range properties {
				if gotProperties[key] != wantValue {
					t.Errorf("value[%q][%q] = %v, want %v", path, key, gotProperties[key], wantValue)
				}
			}
			continue
		}
		if operation["value"] != want {
			t.Errorf("value for %q = %v, want %v", path, operation["value"], want)
		}
		if operation["op"] != "replace" {
			t.Errorf("op for %q = %v, want %q", path, operation["op"], "replace")
		}
	}
}

// TestResolveUpdateSecret is a table test over all nine Secret x SecretFile combinations (each
// nil / &"" / &"value"), plus a dedicated row for a SecretFile path that does not exist.
//
// The invariant this table protects: a non-empty Secret always short-circuits before any file
// read -- the three "secret_value_*" rows below must return that secret verbatim regardless of
// SecretFile, and must not surface a file-read error even when SecretFile points at a valid file.
// Secret == nil and Secret == &"" are equivalent ("the caller did not supply a secret") and fall
// through to SecretFile; when SecretFile is also nil or empty, the result is "" -- meaning "leave
// the credential alone", never "blank the credential". A future refactor that changes
// `*updateAccount.Secret != ""` to a bare `updateAccount.Secret != nil`, or that checks SecretFile
// before Secret, must fail this table.
func TestResolveUpdateSecret(t *testing.T) {
	dir := t.TempDir()
	validFile := filepath.Join(dir, "secret.txt")
	if err := os.WriteFile(validFile, []byte("file-secret-content"), 0o600); err != nil {
		t.Fatalf("failed to write test secret file: %v", err)
	}
	missingFile := filepath.Join(dir, "does-not-exist.txt")

	tests := []struct {
		name       string
		secret     *string
		secretFile *string
		want       string
		wantErr    bool
	}{
		{name: "secret_nil_file_nil", secret: nil, secretFile: nil, want: ""},
		{name: "secret_nil_file_empty", secret: nil, secretFile: common.Ptr(""), want: ""},
		{name: "secret_nil_file_valid", secret: nil, secretFile: common.Ptr(validFile), want: "file-secret-content"},
		{name: "secret_empty_file_nil", secret: common.Ptr(""), secretFile: nil, want: ""},
		{name: "secret_empty_file_empty", secret: common.Ptr(""), secretFile: common.Ptr(""), want: ""},
		{name: "secret_empty_file_valid", secret: common.Ptr(""), secretFile: common.Ptr(validFile), want: "file-secret-content"},
		{name: "secret_value_file_nil", secret: common.Ptr("secret-value"), secretFile: nil, want: "secret-value"},
		{name: "secret_value_file_empty", secret: common.Ptr("secret-value"), secretFile: common.Ptr(""), want: "secret-value"},
		// Secret must short-circuit even when SecretFile points at a real, readable file: the
		// result must be the secret, not the file's contents.
		{name: "secret_value_file_valid", secret: common.Ptr("secret-value"), secretFile: common.Ptr(validFile), want: "secret-value"},
		// SecretFile pointing at a nonexistent path must surface the read error -- reachable only
		// because Secret is absent here; a present Secret would short-circuit before this read.
		{name: "secret_nil_file_missing", secret: nil, secretFile: common.Ptr(missingFile), wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			updateAccount := &accountsmodels.IdsecPCloudUpdateAccount{
				AccountID:  "account-1",
				Secret:     tt.secret,
				SecretFile: tt.secretFile,
			}

			got, err := resolveUpdateSecret(updateAccount)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveUpdateSecret() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveUpdateSecret() unexpected error: %v", err)
			}
			if got != tt.want {
				t.Errorf("resolveUpdateSecret() = %q, want %q", got, tt.want)
			}
		})
	}
}
