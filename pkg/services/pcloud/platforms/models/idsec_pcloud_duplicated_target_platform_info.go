package models

// IdsecPCloudDuplicatedTargetPlatformInfo represents the information about a duplicated target platform.
type IdsecPCloudDuplicatedTargetPlatformInfo struct {
	ID          int    `json:"id" mapstructure:"id" desc:"Unique numeric ID of the new (duplicated) platform" flag:"id"`
	PlatformID  string `json:"platform_id" mapstructure:"platform_id" desc:"Unique string ID of the new (duplicated) platform" flag:"platform-id"`
	Name        string `json:"name" mapstructure:"name" desc:"The display name of the new platform" flag:"name"`
	Description string `json:"description,omitempty" mapstructure:"description" desc:"Description of the new platform" flag:"description"`
}
