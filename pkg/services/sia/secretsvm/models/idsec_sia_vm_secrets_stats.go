package models

// IdsecSIAVMSecretsStats represents the statistics of secrets in a VM.
type IdsecSIAVMSecretsStats struct {
	SecretsCount         int            `json:"secrets_count" mapstructure:"secrets_count" flag:"secrets-count" desc:"The overall number of Secrets."`
	ActiveSecretsCount   int            `json:"active_secrets_count" mapstructure:"active_secrets_count" flag:"active-secrets-count" desc:"The overall number of of active Secrets."`
	InactiveSecretsCount int            `json:"inactive_secrets_count" mapstructure:"inactive_secrets_count" flag:"inactive-secrets-count" desc:"The overall number of inactive Secrets."`
	SecretsCountByType   map[string]int `json:"secrets_count_by_type" mapstructure:"secrets_count_by_type" flag:"secrets-count-by-type" desc:"The number of Secrets by type."`
}
