package models

// IdsecPCloudAddSafe represents the details required to add a safe.
type IdsecPCloudAddSafe struct {
	SafeName                  string `json:"safe_name,omitempty" mapstructure:"safe_name" desc:"The unique name of the Safe (Do not use the following characters: \\ / : * < > . | ? “% & +" flag:"safe-name" validate:"required"`
	Description               string `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the Safe" flag:"description"`
	Location                  string `json:"location,omitempty" mapstructure:"location,omitempty" desc:"Location of the Safe in the Vault" flag:"location" default:"\\"`
	NumberOfDaysRetention     *int   `json:"number_of_days_retention,omitempty" mapstructure:"number_of_days_retention,omitempty" desc:"The number of days that secrets versions are saved in the Safe" flag:"number-of-days-retention"`
	NumberOfVersionsRetention *int   `json:"number_of_versions_retention,omitempty" mapstructure:"number_of_versions_retention,omitempty" desc:"The number of retained versions of every secret that is stored in the Safe" flag:"number-of-versions-retention"`
	AutoPurgeEnabled          bool   `json:"auto_purge_enabled,omitempty" mapstructure:"auto_purge_enabled,omitempty" desc:"Whether to automatically purge files after the end of the Object History Retention Period defined in the Safe properties. Note: Report Safes and PSM Recording Safes are automatically set to Yes and cannot be automatically rotated" flag:"auto-purge-enabled" default:"false"`
	OlacEnabled               bool   `json:"olac_enabled,omitempty" mapstructure:"olac_enabled,omitempty" desc:"Whether to enable Object Level Access Control for the new Safe" flag:"olac-enabled" default:"false"`
	ManagingCPM               string `json:"managing_cpm,omitempty" mapstructure:"managing_cpm,omitempty" desc:"The name of the CPM user who will manage the new Safe" flag:"managing-cpm"`
}
