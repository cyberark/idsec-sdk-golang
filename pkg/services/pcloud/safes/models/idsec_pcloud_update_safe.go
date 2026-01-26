package models

// IdsecPCloudUpdateSafe represents the request to update a safe in the PCloud vault.
type IdsecPCloudUpdateSafe struct {
	SafeID                    string `json:"safe_id,omitempty" desc:"The URL encoding of the Safe name you want to update. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
	SafeName                  string `json:"safe_name,omitempty" mapstructure:"safe_name,omitempty" desc:"The unique name of the Safe. Do not enter special characters: \\ / : * < > . | ? “% & +" flag:"safe-name"`
	Description               string `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the safe" flag:"description"`
	Location                  string `json:"location,omitempty" mapstructure:"location,omitempty" desc:"Location of the safe in the Vault" flag:"location" default:""`
	NumberOfDaysRetention     *int   `json:"number_of_days_retention,omitempty" mapstructure:"number_of_days_retention,omitempty" desc:"The number of days that secrets versions are saved in the Safe. Specify either this parameter or NumberOfVersionsRetention. If you specify this parameter, the NumberOfVersionsRetention parameter is disabled" flag:"number-of-days-retention"`
	NumberOfVersionsRetention *int   `json:"number_of_versions_retention,omitempty" mapstructure:"number_of_versions_retention,omitempty" desc:"The number of retained versions of every secret that is stored in the Safe. Specify either this parameter or NumberOfDaysRetention. If you specify this parameter, the NumberOfDaysRetention parameter is disabled" flag:"number-of-versions-retention"`
	AutoPurgeEnabled          bool   `json:"auto_purge_enabled,omitempty" mapstructure:"auto_purge_enabled,omitempty" desc:"Whether or not to automatically purge files after the end of the Object History Retention Period defined in the Safe properties. Report Safes and PSM Recording Safes are created automatically with AutoPurgeEnabled set to Yes, and cannot be set for automatic management" flag:"auto-purge-enabled" default:"false"`
	OlacEnabled               bool   `json:"olac_enabled,omitempty" mapstructure:"olac_enabled,omitempty" desc:"Whether or not to enable Object Level Access Control for the Safe" flag:"olac-enabled" default:"false"`
	ManagingCPM               string `json:"managing_cpm,omitempty" mapstructure:"managing_cpm,omitempty" desc:"The name of the CPM user who manages the Safe" flag:"managing-cpm"`
}
