package models

// IdsecPCloudListSafeMembers represents the details required to list the members of a safe.
type IdsecPCloudListSafeMembers struct {
	SafeID string `json:"safe_id" mapstructure:"safe_id" desc:"Which safe id to list the members on" flag:"safe-id" validate:"required"`
}
