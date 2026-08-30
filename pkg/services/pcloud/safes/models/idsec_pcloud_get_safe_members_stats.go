package models

// IdsecPCloudGetSafeMembersStats represents the details required to get a safe's members stats.
type IdsecPCloudGetSafeMembersStats struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding the Safe name to retrive the Safe's members statistics" flag:"safe-id" validate:"required"`
}
