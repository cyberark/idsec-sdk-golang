package models

import (
	"encoding/json"
	"fmt"
)

// IdsecSIAVMSecretInfo represents the information about a secret in a VM.
type IdsecSIAVMSecretInfo struct {
	SecretID      string `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"ID of the secret"`
	TenantID      string `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" flag:"tenant-id" desc:"Tenant ID of the secret"`
	SecretType    string `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" desc:"Type of the secret" choices:"ProvisionerUser,PCloudAccount"`
	SecretName    string `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"A friendly name label"`
	SecretDetails string `json:"secret_details" mapstructure:"secret_details" flag:"secret-details" desc:"Secret extra details as JSON string"`
	IsActive      bool   `json:"is_active" mapstructure:"is_active" flag:"is-active" desc:"Whether this secret is active or not"`
}

// GetSecretDetailsMap parses the SecretDetails JSON string into a map.
// Returns an empty map if SecretDetails is empty or invalid JSON.
func (s *IdsecSIAVMSecretInfo) GetSecretDetailsMap() (map[string]interface{}, error) {
	if s.SecretDetails == "" {
		return map[string]interface{}{}, nil
	}
	var details map[string]interface{}
	err := json.Unmarshal([]byte(s.SecretDetails), &details)
	if err != nil {
		return nil, fmt.Errorf("failed to parse secret_details: %w", err)
	}
	return details, nil
}
