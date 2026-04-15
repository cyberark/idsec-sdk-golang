package models

import (
	"reflect"
	"testing"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	policycommonmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/policy/common/models"
)

var (
	validGroupAccessItem = IdsecPolicyGroupAccessTargetItem{
		GroupID:       "11111111-1111-1111-1111-111111111111",
		DirectoryID:   "22222222-2222-2222-2222-222222222222",
		GroupName:     "example-group",
		DirectoryName: "Tenant-Prod",
		Description:   "Access for contractors",
		GroupType:     "security",
	}
)

// TestNewIdsecPolicyGroupAccessTarget covers constructor validation paths.
func TestNewIdsecPolicyGroupAccessTarget(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		target, err := NewIdsecPolicyGroupAccessTarget([]IdsecPolicyGroupAccessTargetItem{validGroupAccessItem})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if target == nil {
			t.Fatal("expected non-nil target")
		}
		if !reflect.DeepEqual(target.Targets, []IdsecPolicyGroupAccessTargetItem{validGroupAccessItem}) {
			t.Fatalf("targets mismatch: %+v", target.Targets)
		}
	})

	t.Run("success_optional_fields_empty", func(t *testing.T) {
		item := IdsecPolicyGroupAccessTargetItem{
			GroupID:     "id",
			DirectoryID: "dir",
		}
		target, err := NewIdsecPolicyGroupAccessTarget([]IdsecPolicyGroupAccessTargetItem{item})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(target.Targets, []IdsecPolicyGroupAccessTargetItem{item}) {
			t.Fatalf("targets mismatch: %+v", target.Targets)
		}
	})

	t.Run("error_empty_slice", func(t *testing.T) {
		if _, err := NewIdsecPolicyGroupAccessTarget(nil); err == nil || err.Error() != "targets cannot be empty" {
			t.Fatalf("expected targets cannot be empty error, got %v", err)
		}
	})

	t.Run("error_missing_field", func(t *testing.T) {
		items := []IdsecPolicyGroupAccessTargetItem{
			{
				GroupID:     "id",
				DirectoryID: "",
			},
		}
		_, err := NewIdsecPolicyGroupAccessTarget(items)
		if err == nil || err.Error() != "target index 0 has empty mandatory field(s)" {
			t.Fatalf("expected missing field error, got %v", err)
		}
	})
}

// TestSerialize validates Serialize behaviour.
func TestSerialize(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{Targets: []IdsecPolicyGroupAccessTargetItem{validGroupAccessItem}}
		out, err := target.Serialize()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rawTargets, ok := out["targets"].([]interface{})
		if !ok || len(rawTargets) != 1 {
			t.Fatalf("expected targets slice with one entry, got %#v", out["targets"])
		}
		first, ok := rawTargets[0].(map[string]interface{})
		if !ok {
			t.Fatalf("expected map entry, got %T", rawTargets[0])
		}
		if first["groupId"] != validGroupAccessItem.GroupID {
			t.Fatalf("expected groupId %s, got %v", validGroupAccessItem.GroupID, first["groupId"])
		}
		if first["directoryId"] != validGroupAccessItem.DirectoryID {
			t.Fatalf("expected directoryId %s, got %v", validGroupAccessItem.DirectoryID, first["directoryId"])
		}
		// GroupName, GroupType, DirectoryName, Description are read-only; must not be serialized to API
		if _, exists := first["groupName"]; exists {
			t.Fatalf("groupName is read-only, must not be in serialized payload")
		}
		if _, exists := first["directoryName"]; exists {
			t.Fatalf("directoryName is read-only, must not be in serialized payload")
		}
		if _, exists := first["description"]; exists {
			t.Fatalf("description is read-only, must not be in serialized payload")
		}
		if _, exists := first["groupType"]; exists {
			t.Fatalf("groupType is read-only, must not be in serialized payload")
		}
	})

	t.Run("success_read_only_fields_omitted", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{
			Targets: []IdsecPolicyGroupAccessTargetItem{
				{GroupID: "id", DirectoryID: "dir"},
			},
		}
		out, err := target.Serialize()
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		rawTargets, ok := out["targets"].([]interface{})
		if !ok || len(rawTargets) != 1 {
			t.Fatalf("expected single target, got %#v", out["targets"])
		}
		first, ok := rawTargets[0].(map[string]interface{})
		if !ok {
			t.Fatalf("expected map entry, got %T", rawTargets[0])
		}
		if _, exists := first["groupName"]; exists {
			t.Fatalf("did not expect groupName key in serialized map")
		}
		if _, exists := first["directoryName"]; exists {
			t.Fatalf("did not expect directoryName key in serialized map")
		}
		if _, exists := first["description"]; exists {
			t.Fatalf("did not expect description key in serialized map")
		}
		if _, exists := first["groupType"]; exists {
			t.Fatalf("did not expect groupType key in serialized map")
		}
	})

	t.Run("error_empty_targets", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{}
		if _, err := target.Serialize(); err == nil || err.Error() != "targets cannot be empty" {
			t.Fatalf("expected error for empty targets, got %v", err)
		}
	})

	t.Run("error_missing_field", func(t *testing.T) {
		target := IdsecPolicyGroupAccessTarget{
			Targets: []IdsecPolicyGroupAccessTargetItem{
				{GroupID: "", DirectoryID: "dir"},
			},
		}
		if _, err := target.Serialize(); err == nil || err.Error() != "target index 0 has empty mandatory field(s)" {
			t.Fatalf("expected missing field error, got %v", err)
		}
	})
}

// TestDeserialize validates Deserialize behaviour.
func TestDeserialize(t *testing.T) {
	t.Parallel()

	t.Run("success", func(t *testing.T) {
		input := map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{
					"group_id":       validGroupAccessItem.GroupID,
					"directory_id":   validGroupAccessItem.DirectoryID,
					"group_name":     validGroupAccessItem.GroupName,
					"directory_name": validGroupAccessItem.DirectoryName,
					"description":    validGroupAccessItem.Description,
					"group_type":     validGroupAccessItem.GroupType,
				},
			},
		}
		target := &IdsecPolicyGroupAccessTarget{}
		if err := target.Deserialize(input); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !reflect.DeepEqual(target.Targets, []IdsecPolicyGroupAccessTargetItem{validGroupAccessItem}) {
			t.Fatalf("unexpected targets: %+v", target.Targets)
		}
	})

	t.Run("success_optional_fields_missing", func(t *testing.T) {
		input := map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{
					"group_id":     "id",
					"directory_id": "dir",
				},
			},
		}
		target := &IdsecPolicyGroupAccessTarget{}
		if err := target.Deserialize(input); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		expected := []IdsecPolicyGroupAccessTargetItem{
			{GroupID: "id", DirectoryID: "dir"},
		}
		if !reflect.DeepEqual(target.Targets, expected) {
			t.Fatalf("unexpected targets: %+v", target.Targets)
		}
	})

	t.Run("error_nil_data", func(t *testing.T) {
		target := &IdsecPolicyGroupAccessTarget{}
		if err := target.Deserialize(nil); err == nil || err.Error() != "data cannot be nil" {
			t.Fatalf("expected nil data error, got %v", err)
		}
	})

	t.Run("error_missing_targets_key", func(t *testing.T) {
		target := &IdsecPolicyGroupAccessTarget{}
		if err := target.Deserialize(map[string]interface{}{"foo": "bar"}); err == nil || err.Error() != "targets missing or not an array" {
			t.Fatalf("expected missing targets error, got %v", err)
		}
	})

	t.Run("error_target_not_map", func(t *testing.T) {
		target := &IdsecPolicyGroupAccessTarget{}
		err := target.Deserialize(map[string]interface{}{"targets": []interface{}{"not-map"}})
		if err == nil || err.Error() != "target index 0 is not a map" {
			t.Fatalf("expected target not map error, got %v", err)
		}
	})

	t.Run("error_missing_fields", func(t *testing.T) {
		target := &IdsecPolicyGroupAccessTarget{}
		err := target.Deserialize(map[string]interface{}{
			"targets": []interface{}{
				map[string]interface{}{
					"group_id":     "",
					"directory_id": "dir",
				},
			},
		})
		if err == nil || err.Error() != "target index 0 has empty mandatory field(s)" {
			t.Fatalf("expected missing field error, got %v", err)
		}
	})
}

// TestSerializeGroupAccessPolicyTargets ensures that SerializeJSONCamel produces the expected structure for the policy wrapper.
func TestSerializeGroupAccessPolicyTargets(t *testing.T) {
	t.Parallel()

	policy := IdsecPolicyGroupAccessPolicy{
		IdsecPolicyCommonAccessPolicy: policycommonmodels.IdsecPolicyCommonAccessPolicy{
			Metadata: policycommonmodels.IdsecPolicyMetadata{
				Name: "example-policy",
				PolicyEntitlement: policycommonmodels.IdsecPolicyEntitlement{
					TargetCategory: commonmodels.CategoryTypeGroupAccess,
					LocationType:   "Azure",
					PolicyType:     policycommonmodels.PolicyTypeRecurring,
				},
			},
		},
		Conditions: policycommonmodels.IdsecPolicyConditions{
			MaxSessionDuration: 1,
		},
		Targets: IdsecPolicyGroupAccessTarget{
			Targets: []IdsecPolicyGroupAccessTargetItem{
				validGroupAccessItem,
			},
		},
	}

	out, err := common.SerializeJSONCamel(policy)
	if err != nil {
		t.Fatalf("unexpected error serializing policy: %v", err)
	}

	rawTargets, ok := out["targets"].(map[string]interface{})
	if !ok {
		t.Fatalf("expected targets to be a map wrapper, got %T", out["targets"])
	}

	inner, ok := rawTargets["targets"].([]interface{})
	if !ok || len(inner) != 1 {
		t.Fatalf("expected inner targets slice with one entry, got %#v", rawTargets["targets"])
	}
	first, ok := inner[0].(map[string]interface{})
	if !ok {
		t.Fatalf("expected first target to be a map, got %T", inner[0])
	}
	if first["groupId"] != validGroupAccessItem.GroupID {
		t.Fatalf("expected groupId %q, got %v", validGroupAccessItem.GroupID, first["groupId"])
	}
	if first["groupName"] != validGroupAccessItem.GroupName {
		t.Fatalf("expected groupName %q, got %v", validGroupAccessItem.GroupName, first["groupName"])
	}
	if first["directoryName"] != validGroupAccessItem.DirectoryName {
		t.Fatalf("expected directoryName %q, got %v", validGroupAccessItem.DirectoryName, first["directoryName"])
	}
	if first["description"] != validGroupAccessItem.Description {
		t.Fatalf("expected description %q, got %v", validGroupAccessItem.Description, first["description"])
	}
	if first["groupType"] != validGroupAccessItem.GroupType {
		t.Fatalf("expected groupType %q, got %v", validGroupAccessItem.GroupType, first["groupType"])
	}
}
