package models

// IdsecPCloudPlatformsFilter represents the filter criteria for listing platforms.
type IdsecPCloudPlatformsFilter struct {
	Active       bool   `json:"active,omitempty" mapstructure:"active" desc:"Filter by active status - if active or inactive" flag:"active"`
	PlatformType string `json:"platform_type,omitempty" mapstructure:"platform_type" desc:"Filter platforms by type" flag:"platform-type"`
	PlatformName string `json:"platform_name,omitempty" mapstructure:"platform_name" desc:"Filter platforms by name" flag:"platform-name"`
}
