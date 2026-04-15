package models

// IdsecPCloudDeactivateTargetPlatform represents the details required to deactivate a target platform.
type IdsecPCloudDeactivateTargetPlatform struct {
	TargetPlatformID int `json:"target_platform_id" mapstructure:"target_platform_id" desc:"ID of the platform to deactivate" flag:"target-platform-id" validate:"required"`
}
