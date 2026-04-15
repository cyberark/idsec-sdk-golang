package models

// IdsecPCloudActivateTargetPlatform represents the details required to activate a target platform.
type IdsecPCloudActivateTargetPlatform struct {
	TargetPlatformID int `json:"target_platform_id" mapstructure:"target_platform_id" desc:"ID of the platform to activate" flag:"target-platform-id" validate:"required"`
}
