package models

// IdsecPCloudGetPlatform represents the details required to retrieve a platform.
type IdsecPCloudGetPlatform struct {
	PlatformID string `json:"platform_id" mapstructure:"platform_id" desc:"Unique numeric ID of the platform" flag:"platform-id" validate:"required"`
}
