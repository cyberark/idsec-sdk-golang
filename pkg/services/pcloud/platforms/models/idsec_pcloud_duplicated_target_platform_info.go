package models

// IdsecPCloudDuplicatedTargetPlatformInfo represents the information about a duplicated target platform.
type IdsecPCloudDuplicatedTargetPlatformInfo struct {
	ID          int    `json:"id" mapstructure:"id" desc:"ID of the duplicated platform" flag:"id"`
	PlatformID  string `json:"platform_id" mapstructure:"platform_id" desc:"Platform id of the duplicated platform" flag:"platform-id"`
	Name        string `json:"name" mapstructure:"name" desc:"New duplicated target platform name" flag:"name"`
	Description string `json:"description,omitempty" mapstructure:"description" desc:"New duplicated target platform description" flag:"description"`
}
