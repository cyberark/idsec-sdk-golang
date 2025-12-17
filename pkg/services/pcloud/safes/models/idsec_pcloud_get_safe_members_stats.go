package models

// IdsecPCloudGetSafeMembersStats represents the details required to get a safe's members stats.
type IdsecPCloudGetSafeMembersStats struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"Safe url id to get the members stats for" flag:"safe-id" validate:"required"`
}
