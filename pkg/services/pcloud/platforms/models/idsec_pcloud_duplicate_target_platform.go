package models

// IdsecPCloudDuplicateTargetPlatform represents the details required to duplicate a target platform.
type IdsecPCloudDuplicateTargetPlatform struct {
	TargetPlatformID int    `json:"target_platform_id" mapstructure:"target_platform_id" desc:"ID of the platform to duplicate" flag:"target-platform-id" validate:"required"`
	Name             string `json:"name" mapstructure:"name" desc:"Name of the new platform" flag:"name" validate:"required"`
	Description      string `json:"description,omitempty" mapstructure:"description" desc:"Description of the new platform" flag:"description"`
}
