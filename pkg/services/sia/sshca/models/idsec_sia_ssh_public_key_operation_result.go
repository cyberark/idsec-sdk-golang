package models

// IdsecSIASSHPublicKeyOperationResult represents the result of an SSH public key operation
type IdsecSIASSHPublicKeyOperationResult struct {
	Result  bool   `json:"result" mapstructure:"result" desc:"Result of the SSH public key operation"`
	Message string `json:"message" mapstructure:"message" desc:"Message providing additional information about the operation result"`
}
