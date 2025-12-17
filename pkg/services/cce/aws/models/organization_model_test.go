package models

import (
	"testing"

	"github.com/mitchellh/mapstructure"
	ccemodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/common/models"
)

// TestPropertyValue_SerializeDeserialize tests union type for property values
func TestPropertyValue_SerializeDeserialize(t *testing.T) {
	// Test bool
	boolVal := true
	boolProp := ccemodels.IdsecCCEPropertyValue{BoolValue: &boolVal}

	result, err := boolProp.Serialize()
	if err != nil {
		t.Fatalf("Serialize bool failed: %v", err)
	}
	if result != true {
		t.Errorf("expected true, got %v", result)
	}

	var deserializedBool ccemodels.IdsecCCEPropertyValue
	if err := deserializedBool.Deserialize(true); err != nil {
		t.Fatalf("Deserialize bool failed: %v", err)
	}
	if deserializedBool.BoolValue == nil || *deserializedBool.BoolValue != true {
		t.Error("Bool value not deserialized correctly")
	}

	// Test string
	strVal := "include"
	strProp := ccemodels.IdsecCCEPropertyValue{StringValue: &strVal}

	result, err = strProp.Serialize()
	if err != nil {
		t.Fatalf("Serialize string failed: %v", err)
	}
	if result != "include" {
		t.Errorf("expected 'include', got %v", result)
	}

	var deserializedStr ccemodels.IdsecCCEPropertyValue
	if err := deserializedStr.Deserialize("include"); err != nil {
		t.Fatalf("Deserialize string failed: %v", err)
	}
	if deserializedStr.StringValue == nil || *deserializedStr.StringValue != "include" {
		t.Error("String value not deserialized correctly")
	}
}

// TestOrganization_BasicDeserialization tests basic Organization deserialization
func TestOrganization_BasicDeserialization(t *testing.T) {
	// Simulate API response data (after DeserializeJSONSnake - snake_case keys)
	data := map[string]interface{}{
		"id":                    "org-123",
		"organization_root_id":  "r-abcd1234",
		"management_account_id": "123456789012",
		"organization_id":       "o-abc123def",
		"onboarding_type":       "programmatic",
		"parameters": map[string]interface{}{
			"dpa": map[string]interface{}{
				"region": "us-east-1",
			},
		},
		"status": "Completely added",
	}

	// Decode with mapstructure (what service does)
	var org TfIdsecCCEAWSOrganization
	err := mapstructure.Decode(data, &org)
	if err != nil {
		t.Fatalf("mapstructure.Decode failed: %v", err)
	}

	// Verify basic fields
	if org.ID != "org-123" {
		t.Errorf("expected ID org-123, got %s", org.ID)
	}

	// Verify Parameters
	if len(org.Parameters) == 0 {
		t.Fatal("Parameters should not be empty")
	}
	if org.Parameters["dpa"]["region"] != "us-east-1" {
		t.Errorf("Parameters dpa not deserialized correctly")
	}
}
