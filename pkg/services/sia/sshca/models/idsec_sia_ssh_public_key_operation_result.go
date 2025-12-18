package models

// IdsecSIASSHPublicKeyOperationResult represents the result of an SSH public key operation
type IdsecSIASSHPublicKeyOperationResult struct {
	Result  bool   `json:"result" mapstructure:"result" desc:"The result of the SSH public key operation."`
	Message string `json:"message" mapstructure:"message" desc:"The message that provides additional information about the operation result."`
}
