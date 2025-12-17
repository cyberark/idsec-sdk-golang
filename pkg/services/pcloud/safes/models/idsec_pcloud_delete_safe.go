package models

// IdsecPCloudDeleteSafe represents the details required to delete a safe.
type IdsecPCloudDeleteSafe struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"Safe id to delete" flag:"safe-id" validate:"required"`
}
