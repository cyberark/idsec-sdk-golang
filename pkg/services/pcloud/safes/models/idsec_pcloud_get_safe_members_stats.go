package models

// IdsecPCloudGetSafeMembersStats represents the details required to get a safe's members stats.
type IdsecPCloudGetSafeMembersStats struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"The Vault user name, Domain user name or group name of the Safe member" flag:"safe-id" validate:"required"`
}
