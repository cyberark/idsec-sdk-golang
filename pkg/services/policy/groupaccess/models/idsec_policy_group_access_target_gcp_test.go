package models

import (
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
)

var (
	validGCPGroupAccessItem = IdsecPolicyGroupAccessGCPTarget{
		GroupID:          "groups/01234abcde",
		OrganizationID:   "123456789012",
		GroupName:        "gcp-admins",
		OrganizationName: "Example Org",
		Description:      "GCP admins group",
	}
)

// TestGCPTargetSerialize validates the GCP target write payload.
func TestGCPTargetSerialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		target    IdsecPolicyGroupAccessGCPTarget
		expected  map[string]interface{}
		expectErr bool
	}{
		{
			name:     "success_read_only_fields_omitted",
			target:   validGCPGroupAccessItem,
			expected: map[string]interface{}{"groupId": "groups/01234abcde", "organizationId": "123456789012"},
		},
		{name: "error_missing_group_id", target: IdsecPolicyGroupAccessGCPTarget{OrganizationID: "123456789012"}, expectErr: true},
		{name: "error_missing_organization_id", target: IdsecPolicyGroupAccessGCPTarget{GroupID: "groups/01234abcde"}, expectErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			out, err := tc.target.Serialize()
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got payload %#v", out)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(out, tc.expected) {
				t.Fatalf("expected %#v, got %#v", tc.expected, out)
			}
		})
	}
}

// TestGCPTargetDeserialize validates the GCP target parsing for snake_case and camelCase payloads.
func TestGCPTargetDeserialize(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		input     map[string]interface{}
		expected  IdsecPolicyGroupAccessGCPTarget
		expectErr bool
	}{
		{
			name: "success_snake_case",
			input: map[string]interface{}{
				"group_id":          validGCPGroupAccessItem.GroupID,
				"organization_id":   validGCPGroupAccessItem.OrganizationID,
				"group_name":        validGCPGroupAccessItem.GroupName,
				"organization_name": validGCPGroupAccessItem.OrganizationName,
				"description":       validGCPGroupAccessItem.Description,
			},
			expected: validGCPGroupAccessItem,
		},
		{
			name: "success_camel_case",
			input: map[string]interface{}{
				"groupId":          validGCPGroupAccessItem.GroupID,
				"organizationId":   validGCPGroupAccessItem.OrganizationID,
				"groupName":        validGCPGroupAccessItem.GroupName,
				"organizationName": validGCPGroupAccessItem.OrganizationName,
				"description":      validGCPGroupAccessItem.Description,
			},
			expected: validGCPGroupAccessItem,
		},
		{
			name:     "success_null_read_only_fields",
			input:    map[string]interface{}{"group_id": "groups/1", "organization_id": "1", "organization_name": nil, "description": nil},
			expected: IdsecPolicyGroupAccessGCPTarget{GroupID: "groups/1", OrganizationID: "1"},
		},
		{name: "error_missing_organization_id", input: map[string]interface{}{"group_id": "groups/1"}, expectErr: true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			var target IdsecPolicyGroupAccessGCPTarget
			err := target.Deserialize(tc.input)
			if tc.expectErr {
				if err == nil {
					t.Fatalf("expected error, got %+v", target)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(target, tc.expected) {
				t.Fatalf("expected %+v, got %+v", tc.expected, target)
			}
		})
	}
}

// TestNewIdsecPolicyGroupAccessGCPTarget covers GCP constructor validation paths.
func TestNewIdsecPolicyGroupAccessGCPTarget(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		target, err := NewIdsecPolicyGroupAccessGCPTarget([]IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(target.Targets) != 0 || !reflect.DeepEqual(target.GCPTargets, []IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem}) {
			t.Fatalf("unexpected wrapper: %+v", target)
		}
	})

	t.Run("error_empty_slice", func(t *testing.T) {
		if _, err := NewIdsecPolicyGroupAccessGCPTarget(nil); err == nil || err.Error() != "gcp_targets cannot be empty" {
			t.Fatalf("expected gcp_targets cannot be empty error, got %v", err)
		}
	})

	t.Run("error_missing_field", func(t *testing.T) {
		_, err := NewIdsecPolicyGroupAccessGCPTarget([]IdsecPolicyGroupAccessGCPTarget{{GroupID: "groups/1"}})
		if err == nil || err.Error() != "gcp_targets index 0 has empty mandatory field(s)" {
			t.Fatalf("expected missing field error, got %v", err)
		}
	})
}

// TestSerializeTargets validates the location_type aware wrapper serialization.
func TestSerializeTargets(t *testing.T) {
	t.Parallel()

	t.Run("success_azure_matches_legacy_payload", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{validGroupAccessItem}}
		legacy, err := common.SerializeJSONCamel(target)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out, err := target.SerializeTargets("Azure")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(out, legacy) {
			t.Fatalf("azure payload changed:\nlegacy: %#v\nnew:    %#v", legacy, out)
		}
	})

	t.Run("success_gcp", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{GCPTargets: []IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem}}
		out, err := target.SerializeTargets("GCP")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{"groupId": "groups/01234abcde", "organizationId": "123456789012"},
			},
		}
		if !reflect.DeepEqual(out, expected) {
			t.Fatalf("expected %#v, got %#v", expected, out)
		}
	})

	t.Run("success_location_type_case_insensitive", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{GCPTargets: []IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem}}
		if _, err := target.SerializeTargets("gcp"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	errorTests := []struct {
		name         string
		target       IdsecPolicyGroupAccessTarget
		locationType string
		expectMsg    string
	}{
		{
			name:         "error_empty",
			target:       IdsecPolicyGroupAccessTarget{},
			locationType: "Azure",
			expectMsg:    "targets cannot be empty",
		},
		{
			name: "error_both_lists",
			target: IdsecPolicyGroupAccessTarget{
				Targets:    []IdsecPolicyGroupAccessAzureTarget{validGroupAccessItem},
				GCPTargets: []IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem},
			},
			locationType: "GCP",
			expectMsg:    "targets and gcp_targets cannot both be set; a group access policy targets a single cloud provider",
		},
		{
			name:         "error_gcp_targets_with_azure_location",
			target:       IdsecPolicyGroupAccessTarget{GCPTargets: []IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem}},
			locationType: "Azure",
			expectMsg:    "location_type Azure requires targets, got gcp_targets",
		},
		{
			name:         "error_azure_targets_with_gcp_location",
			target:       IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{validGroupAccessItem}},
			locationType: "GCP",
			expectMsg:    "location_type GCP requires gcp_targets, got targets",
		},
		{
			name:         "error_unsupported_location",
			target:       IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{validGroupAccessItem}},
			locationType: "AWS",
			expectMsg:    `unsupported location_type "AWS" for group access policy, expected Azure or GCP`,
		},
		{
			name:         "error_azure_missing_field",
			target:       IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{{GroupID: "id"}}},
			locationType: "Azure",
			expectMsg:    "target index 0 has empty mandatory field(s)",
		},
		{
			name:         "error_gcp_missing_field",
			target:       IdsecPolicyGroupAccessTarget{GCPTargets: []IdsecPolicyGroupAccessGCPTarget{{GroupID: "groups/1"}}},
			locationType: "GCP",
			expectMsg:    "gcp_targets index 0 has empty mandatory field(s)",
		},
	}
	for _, tc := range errorTests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			if _, err := tc.target.SerializeTargets(tc.locationType); err == nil || err.Error() != tc.expectMsg {
				t.Fatalf("expected error %q, got %v", tc.expectMsg, err)
			}
		})
	}
}

// TestDeserializeTargets validates routing of API targets by location_type.
func TestDeserializeTargets(t *testing.T) {
	t.Parallel()

	gcpPayload := map[string]interface{}{
		"targets": []interface{}{
			map[string]interface{}{
				"group_id":          validGCPGroupAccessItem.GroupID,
				"organization_id":   validGCPGroupAccessItem.OrganizationID,
				"group_name":        validGCPGroupAccessItem.GroupName,
				"organization_name": validGCPGroupAccessItem.OrganizationName,
				"description":       validGCPGroupAccessItem.Description,
			},
		},
	}

	t.Run("success_gcp_routes_to_gcp_targets", func(t *testing.T) {
		// mapstructure decodes GCP items into the Azure list first; DeserializeTargets must move them.
		target := IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{{GroupID: validGCPGroupAccessItem.GroupID}}}
		if err := target.DeserializeTargets(gcpPayload, "GCP"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Targets != nil {
			t.Fatalf("expected azure targets cleared, got %+v", target.Targets)
		}
		if !reflect.DeepEqual(target.GCPTargets, []IdsecPolicyGroupAccessGCPTarget{validGCPGroupAccessItem}) {
			t.Fatalf("unexpected gcp targets: %+v", target.GCPTargets)
		}
	})

	t.Run("success_azure_left_unchanged", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessAzureTarget{validGroupAccessItem}}
		if err := target.DeserializeTargets(gcpPayload, "Azure"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(target.Targets, []IdsecPolicyGroupAccessAzureTarget{validGroupAccessItem}) || target.GCPTargets != nil {
			t.Fatalf("azure targets must be unchanged, got %+v", target)
		}
	})

	t.Run("success_missing_targets_is_noop", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{}
		if err := target.DeserializeTargets(nil, "GCP"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if err := target.DeserializeTargets(map[string]interface{}{}, "GCP"); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target.Targets != nil || target.GCPTargets != nil {
			t.Fatalf("expected empty wrapper, got %+v", target)
		}
	})

	t.Run("error_targets_not_array", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{}
		if err := target.DeserializeTargets(map[string]interface{}{"targets": "bad"}, "GCP"); err == nil || err.Error() != "targets is not an array" {
			t.Fatalf("expected targets is not an array error, got %v", err)
		}
	})

	t.Run("error_item_not_map", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{}
		err := target.DeserializeTargets(map[string]interface{}{"targets": []interface{}{"bad"}}, "GCP")
		if err == nil || err.Error() != "gcp_targets index 0 is not a map" {
			t.Fatalf("expected item not map error, got %v", err)
		}
	})

	t.Run("error_item_missing_field", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{}
		err := target.DeserializeTargets(map[string]interface{}{"targets": []interface{}{map[string]interface{}{"group_id": "groups/1"}}}, "GCP")
		if err == nil || err.Error() != "gcp_targets index 0 has empty mandatory field(s)" {
			t.Fatalf("expected missing field error, got %v", err)
		}
	})
}
