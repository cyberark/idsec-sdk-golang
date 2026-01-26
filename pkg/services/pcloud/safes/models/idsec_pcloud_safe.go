package models

// IdsecPCloudSafeCreator represents the creator of a safe.
type IdsecPCloudSafeCreator struct {
	ID   string `json:"id" mapstructure:"id" desc:"The ID of the user that created the Safe" flag:"id"`
	Name string `json:"name" mapstructure:"name" desc:"The name of the user that created the Safe" flag:"name"`
}

// IdsecPCloudSafe represents a safe with additional details.
type IdsecPCloudSafe struct {
	SafeName                  string                 `json:"safe_name,omitempty" mapstructure:"safe_name" desc:"The unique ID of the Safe used when calling Safe APIs" flag:"safe-name"`
	Description               string                 `json:"description,omitempty" mapstructure:"description" desc:"The description of the Safe" flag:"description"`
	Location                  string                 `json:"location,omitempty" mapstructure:"location" desc:"The location of the Safe in the Vault" flag:"location" default:"\\"`
	NumberOfDaysRetention     int                    `json:"number_of_days_retention,omitempty" mapstructure:"number_of_days_retention" desc:"The number of days that secrets versions are saved in the Safe" flag:"number-of-days-retention" default:"7"`
	NumberOfVersionsRetention int                    `json:"number_of_versions_retention,omitempty" mapstructure:"number_of_versions_retention" desc:"The number of retained versions of every secret that is stored in the Safe" flag:"number-of-versions-retention"`
	AutoPurgeEnabled          bool                   `json:"auto_purge_enabled,omitempty" mapstructure:"auto_purge_enabled" desc:"Whether or not to automatically purge files after the end of the Object History Retention Period defined in the Safe properties. For Report Safes and PSM Recording Safes, automatically set to Yes" flag:"auto-purge-enabled" default:"false"`
	OlacEnabled               bool                   `json:"olac_enabled,omitempty" mapstructure:"olac_enabled" desc:"Whether Object Level Access Control is enabled" flag:"olac-enabled" default:"false"`
	ManagingCPM               string                 `json:"managing_cpm,omitempty" mapstructure:"managing_cpm" desc:"The managing CPM of the Safe" flag:"managing-cpm"`
	Creator                   IdsecPCloudSafeCreator `json:"creator,omitempty" mapstructure:"creator" desc:"Name/ID of the user that created the Safe" flag:"creator"`
	CreationTime              int                    `json:"creation_time,omitempty" mapstructure:"creation_time" desc:"The Unix creation time of the Safe" flag:"creation-time"`
	LastModificationTime      int                    `json:"last_modification_time,omitempty" mapstructure:"last_modification_time" desc:"The Unix time when the Safe was last updated" flag:"last-modification-time"`
	SafeID                    string                 `json:"safe_id" mapstructure:"safe_id" desc:"The unique ID of the Safe used when calling Safe APIs" flag:"safe-id"`
	SafeNumber                int                    `json:"safe_number,omitempty" mapstructure:"safe_number" desc:"The unique numerical ID of the Safe" flag:"safe-number"`
	IsExpiredMember           bool                   `json:"is_expired_member,omitempty" mapstructure:"is_expired_member" desc:"Whether the membership for the Safe is expired. For expired members, the value is True" flag:"is-expired-member" default:"false"`
}
