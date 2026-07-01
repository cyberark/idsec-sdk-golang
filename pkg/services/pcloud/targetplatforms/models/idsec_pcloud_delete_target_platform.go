package models

// IdsecPCloudDeleteTargetPlatform represents the details required to delete a target platform.
type IdsecPCloudDeleteTargetPlatform struct {
	TargetPlatformID *int `json:"target_platform_id" mapstructure:"target_platform_id" desc:"ID of the platform to delete" flag:"target-platform-id" deprecated:"id,use the new flag"`
	ID               *int `json:"id" mapstructure:"id" desc:"ID of the platform to delete" flag:"id"`
}
