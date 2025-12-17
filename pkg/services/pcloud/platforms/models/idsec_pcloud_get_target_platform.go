package models

// IdsecPCloudGetTargetPlatform represents the details required to retrieve a target platform.
type IdsecPCloudGetTargetPlatform struct {
	TargetPlatformID int `json:"target_platform_id" mapstructure:"target_platform_id" desc:"ID of the platform to get" flag:"target-platform-id" validate:"required"`
}
