package models

// IdsecPCloudImportPlatform represents the details required to import a platform.
type IdsecPCloudImportPlatform struct {
	PlatformZipPath string `json:"platform_zip_path" mapstructure:"platform_zip_path" desc:"Local path of the platform's zip file" flag:"platform-zip-path" validate:"required"`
}
