package models

// IdsecSIADBSecretsStats represents the statistics of secrets in the Idsec SIA DB.
type IdsecSIADBSecretsStats struct {
	SecretsCount             int            `json:"secrets_count" mapstructure:"secrets_count" desc:"The overall number of Secrets."`
	ActiveSecretsCount       int            `json:"active_secrets_count" mapstructure:"active_secrets_count" desc:"The overall number of active Secrets."`
	InactiveSecretsCount     int            `json:"inactive_secrets_count" mapstructure:"inactive_secrets_count" desc:"The overall number of inactive Secrets."`
	SecretsCountBySecretType map[string]int `json:"secrets_count_by_secret_type" mapstructure:"secrets_count_by_secret_type" desc:"The number of Secrets by secret type."`
	SecretsCountByStoreType  map[string]int `json:"secrets_count_by_store_type" mapstructure:"secrets_count_by_store_type" desc:"The number of Secrets by store type."`
}
