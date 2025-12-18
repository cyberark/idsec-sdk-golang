package models

import (
	"encoding/json"
	"fmt"
)

// Possible Secret Types
const (
	ProvisionerUser = "ProvisionerUser"
	PCloudAccount   = "PCloudAccount"
)

// IdsecSIAVMDataMessage represents a data message in the Idsec SIA VM.
type IdsecSIAVMDataMessage struct {
	MessageID string `json:"message_id" mapstructure:"message_id" flag:"message-id" desc:"The data message ID."`
	Data      string `json:"data" mapstructure:"data" flag:"data" desc:"The actual data."`
}

// IdsecSIAVMSecretData represents the secret data in the Idsec SIA VM.
type IdsecSIAVMSecretData struct {
	SecretData      interface{} `json:"secret_data" mapstructure:"secret_data" flag:"secret-data" desc:"The actual Secret data, can be of different types, and is base64 encoded if SecretBytes. Otherwise it is stored in the JIT data message as a string or as a dict of Secret data to be encrypted."`
	TenantEncrypted bool        `json:"tenant_encrypted" mapstructure:"tenant_encrypted" flag:"tenant-encrypted" desc:"Indicates whether the Secret is encrypted by the tenant key."`
}

// IdsecSIAVMSecret represents a secret in the Idsec SIA VM.
type IdsecSIAVMSecret struct {
	SecretID      string               `json:"secret_id" mapstructure:"secret_id" flag:"secret-id" desc:"ID of the secret"`
	TenantID      string               `json:"tenant_id,omitempty" mapstructure:"tenant_id,omitempty" flag:"tenant-id" desc:"Tenant ID of the secret"`
	Secret        IdsecSIAVMSecretData `json:"secret,omitempty" mapstructure:"secret,omitempty" flag:"secret" desc:"Secret itself"`
	SecretType    string               `json:"secret_type" mapstructure:"secret_type" flag:"secret-type" desc:"Type of the secret" choices:"ProvisionerUser,PCloudAccount"`
	SecretDetails string               `json:"secret_details" mapstructure:"secret_details" flag:"secret-details" desc:"Secret extra details as JSON string"`
	IsActive      bool                 `json:"is_active" mapstructure:"is_active" flag:"is-active" desc:"Whether this secret is active or not and can be retrieved or modified"`
	IsRotatable   bool                 `json:"is_rotatable" mapstructure:"is_rotatable" flag:"is-rotatable" desc:"Whether this secret can be rotated"`
	CreationTime  string               `json:"creation_time" mapstructure:"creation_time" flag:"creation-time" desc:"Creation time of the secret"`
	LastModified  string               `json:"last_modified" mapstructure:"last_modified" flag:"last-modified" desc:"Last time the secret was modified"`
	SecretName    string               `json:"secret_name,omitempty" mapstructure:"secret_name,omitempty" flag:"secret-name" desc:"A friendly name label"`
}

// GetSecretDetailsMap parses the SecretDetails JSON string into a map.
// Returns an empty map if SecretDetails is empty or invalid JSON.
func (s *IdsecSIAVMSecret) GetSecretDetailsMap() (map[string]interface{}, error) {
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
