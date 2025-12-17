package models

// IdsecPCloudGetSafe represents the details required to get a safe's details.
type IdsecPCloudGetSafe struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"Safe id to get details for" flag:"safe-id" validate:"required"`
}
