package models

// IdsecPCloudImportTargetPlatform represents the details required to import a target platform.
type IdsecPCloudImportTargetPlatform struct {
	PlatformZipPath string `json:"platform_zip_path" mapstructure:"platform_zip_path" desc:"Local path to the platform zip file" flag:"platform-zip-path" validate:"required"`
}
