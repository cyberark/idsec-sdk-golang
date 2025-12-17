package models

import (
	"testing"
)

// TestSerializeTargets verifies that SerializeTargets produces the expected
// map structure for a variety of populated and empty target lists.
func TestSerializeTargets(t *testing.T) {
	tests := []struct {
		name       string
		target     IdsecUAPSCACloudConsoleTarget
		expectsLen int
		expectsErr bool
	}{
		{
			name: "success_serialize_all_targets",
			target: IdsecUAPSCACloudConsoleTarget{
				AwsAccountTargets:      []IdsecUAPSCAAWSAccountTarget{{IdsecUAPSCATarget: IdsecUAPSCATarget{RoleID: "r1", WorkspaceID: "w1"}}},
				AwsOrganizationTargets: []IdsecUAPSCAAWSOrganizationTarget{{IdsecUAPSCAOrgTarget: IdsecUAPSCAOrgTarget{IdsecUAPSCATarget: IdsecUAPSCATarget{RoleID: "r2", WorkspaceID: "w2"}, OrgID: "org1"}}},
				AzureTargets:           []IdsecUAPSCAAzureTarget{{IdsecUAPSCAOrgTarget: IdsecUAPSCAOrgTarget{IdsecUAPSCATarget: IdsecUAPSCATarget{RoleID: "r3", WorkspaceID: "w3"}, OrgID: "azorg"}, WorkspaceType: AzureWSTypeSubscription, RoleType: 1}},
				GcpTargets:             []IdsecUAPSCAGCPTarget{{IdsecUAPSCAOrgTarget: IdsecUAPSCAOrgTarget{IdsecUAPSCATarget: IdsecUAPSCATarget{RoleID: "r4", WorkspaceID: "w4"}, OrgID: "gcporg"}, WorkspaceType: GCPWSTypeProject, RolePackage: "pkg", RoleType: 2}},
			},
			expectsLen: 4,
			expectsErr: false,
		},
		{
			name:       "serialize_empty",
			target:     IdsecUAPSCACloudConsoleTarget{},
			expectsLen: 0,
			expectsErr: false,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			out, err := tt.target.SerializeTargets()
			if tt.expectsErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			targets, ok := out["targets"].([]interface{})
			if !ok {
				t.Fatalf("expected targets slice, got: %T", out["targets"])
			}
			if len(targets) != tt.expectsLen {
				t.Fatalf("expected %d targets, got %d", tt.expectsLen, len(targets))
			}
		})
	}
}

// TestDeserializeTargets covers successful deserialization of mixed target types
// and multiple error cases such as invalid formats and unknown workspace types.
func TestDeserializeTargets(t *testing.T) {
	tests := []struct {
		name       string
		input      map[string]interface{}
		expects    IdsecUAPSCACloudConsoleTarget
		expectsErr bool
	}{
		{
			name: "success_deserialize_mixed",
			input: map[string]interface{}{"targets": []interface{}{
				map[string]interface{}{"role_id": "r1", "workspace_id": "w1"},
				map[string]interface{}{"role_id": "r2", "workspace_id": "w2", "org_id": "org1"},
				map[string]interface{}{"workspace_type": AzureWSTypeSubscription, "role_id": "r3", "workspace_id": "w3", "org_id": "azorg", "role_type": 1},
				map[string]interface{}{"workspace_type": GCPWSTypeProject, "role_id": "r4", "workspace_id": "w4", "org_id": "gcporg", "role_package": "pkg", "role_type": 2},
			}},
			expectsErr: false,
		},
		{
			name:       "error_invalid_format_targets_not_slice",
			input:      map[string]interface{}{"targets": "not-a-slice"},
			expectsErr: true,
		},
		{
			name:       "error_invalid_target_map",
			input:      map[string]interface{}{"targets": []interface{}{"not-a-map"}},
			expectsErr: true,
		},
		{
			name:       "error_unknown_workspace_type",
			input:      map[string]interface{}{"targets": []interface{}{map[string]interface{}{"workspace_type": "unknown"}}},
			expectsErr: true,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var target IdsecUAPSCACloudConsoleTarget
			err := target.DeserializeTargets(tt.input)
			if tt.expectsErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			// Validate counts for the mixed success case
			if tt.name == "success_deserialize_mixed" {
				if len(target.AwsAccountTargets) != 1 {
					t.Fatalf("expected 1 aws account target, got %d", len(target.AwsAccountTargets))
				}
				if len(target.AwsOrganizationTargets) != 1 {
					t.Fatalf("expected 1 aws org target, got %d", len(target.AwsOrganizationTargets))
				}
				if len(target.AzureTargets) != 1 {
					t.Fatalf("expected 1 azure target, got %d", len(target.AzureTargets))
				}
				if len(target.GcpTargets) != 1 {
					t.Fatalf("expected 1 gcp target, got %d", len(target.GcpTargets))
				}
				// spot-check some fields
				if target.AzureTargets[0].WorkspaceType != AzureWSTypeSubscription {
					t.Fatalf("unexpected azure workspace type: %s", target.AzureTargets[0].WorkspaceType)
				}
				if target.GcpTargets[0].WorkspaceType != GCPWSTypeProject {
					t.Fatalf("unexpected gcp workspace type: %s", target.GcpTargets[0].WorkspaceType)
				}
			}
		})
	}
}

// TestClearTargetsFromData verifies that ClearTargetsFromData removes both snake_case and camelCase keys.
func TestClearTargetsFromData(t *testing.T) {
	data := map[string]interface{}{
		"aws_account_targets":      []interface{}{},
		"awsAccountTargets":        []interface{}{},
		"aws_organization_targets": []interface{}{},
		"awsOrganizationTargets":   []interface{}{},
		"azure_targets":            []interface{}{},
		"azureTargets":             []interface{}{},
		"gcp_targets":              []interface{}{},
		"gcpTargets":               []interface{}{},
	}
	var target IdsecUAPSCACloudConsoleTarget
	target.ClearTargetsFromData(data)
	// none of the keys should remain
	for k := range data {
		t.Fatalf("expected key %s to be removed", k)
	}
}
