package models

// IdsecSecHubSecretStoresStats represents the statistics of secret stores in the Idsec SecHub system.
// It includes the total count of secret stores, a breakdown by creator, and a breakdown by type.
type IdsecSecHubSecretStoresStats struct {
	SecretStoresCount          int            `json:"secret_stores_count" mapstructure:"secret_stores_count" desc:"Overall secret stores count"`
	SecretStoresCountByCreator map[string]int `json:"secret_stores_count_by_creator" mapstructure:"secret_stores_count_by_creator" desc:"Secret Stores count by creator"`
	SecretStoresCountByType    map[string]int `json:"secrect_stores_count_by_type" mapstructure:"secret_stores_count_by_type" desc:"Secret Stores count by type"`
}
