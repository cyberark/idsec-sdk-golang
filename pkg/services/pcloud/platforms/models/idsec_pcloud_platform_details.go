package models

// IdsecPCloudPlatformDetails represents the platform details API response.
//
// This API endpoint returns a different structure than the List Platforms API.
type IdsecPCloudPlatformDetails struct {
	PlatformID string                 `json:"platform_id" mapstructure:"Unique string ID of the platform" desc:"Platform ID" flag:"platform-id"`
	Active     bool                   `json:"active" mapstructure:"active" desc:"Whether the platform is active" flag:"active"`
	Details    map[string]interface{} `json:"details" mapstructure:"details" desc:"Platform configuration details" flag:"details"`
}
