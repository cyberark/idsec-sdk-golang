package models

// IdsecAccessAssetsAsset represents a single infrastructure asset returned by the User Portal service.
type IdsecAccessAssetsAsset struct {
	// Core identifiers
	AssetCategory string `json:"assetCategory,omitempty" mapstructure:"asset_category,omitempty" desc:"Category of the asset"`
	AssetType     string `json:"assetType,omitempty" mapstructure:"asset_type,omitempty" desc:"Type of the asset"`
	AssetID       string `json:"assetId,omitempty" mapstructure:"asset_id,omitempty" desc:"Unique identifier of the asset"`

	// Metadata
	LastAccessed string `json:"lastAccessed,omitempty" mapstructure:"last_accessed,omitempty" desc:"ISO 8601 timestamp of last access"`
	IsFavorite   bool   `json:"isFavorite,omitempty" mapstructure:"is_favorite,omitempty" desc:"Whether the asset is marked as a favorite"`
	LinkType     string `json:"linkType,omitempty" mapstructure:"link_type,omitempty" desc:"Link type of the asset"`
	LinkUID      string `json:"linkUid,omitempty" mapstructure:"link_uid,omitempty" desc:"Link UID of the asset"`

	// Infrastructure connection
	Protocol     string `json:"protocol,omitempty" mapstructure:"protocol,omitempty" desc:"Connection protocol"`
	AccessMethod string `json:"accessMethod,omitempty" mapstructure:"access_method,omitempty" desc:"Access method (vaulted or zsp)"`
	Address      string `json:"address,omitempty" mapstructure:"address,omitempty" desc:"Target address"`
	Domain       string `json:"domain,omitempty" mapstructure:"domain,omitempty" desc:"Domain of the asset"`
	NetworkName  string `json:"networkName,omitempty" mapstructure:"network_name,omitempty" desc:"Network name"`
	PlatformType string `json:"platformType,omitempty" mapstructure:"platform_type,omitempty" desc:"Platform type"`

	// Vaulted credential fields
	Username              string                 `json:"username,omitempty" mapstructure:"username,omitempty" desc:"Username for the asset"`
	PlatformID            string                 `json:"platformId,omitempty" mapstructure:"platform_id,omitempty" desc:"Platform identifier"`
	PlatformSubtype       string                 `json:"platformSubtype,omitempty" mapstructure:"platform_subtype,omitempty" desc:"Platform subtype"`
	WorkflowStatus        map[string]interface{} `json:"workflowStatus,omitempty" mapstructure:"workflow_status,omitempty" desc:"Workflow status details"`
	FileCategories        map[string]interface{} `json:"fileCategories,omitempty" mapstructure:"file_categories,omitempty" desc:"File categories"`
	JitElevateVaultedCred *bool                  `json:"jitElevateVaultedCred,omitempty" mapstructure:"jit_elevate_vaulted_cred,omitempty" desc:"Whether JIT elevation is enabled for vaulted credentials"`

	// Discovery ZSP fields
	OsType       string            `json:"osType,omitempty" mapstructure:"os_type,omitempty" desc:"Operating system type"`
	Protocols    map[string]string `json:"protocols,omitempty" mapstructure:"protocols,omitempty" desc:"Available protocols"`
	Ips          []string          `json:"ips,omitempty" mapstructure:"ips,omitempty" desc:"IP addresses"`
	WorkspaceID  string            `json:"workspaceId,omitempty" mapstructure:"workspace_id,omitempty" desc:"Workspace identifier"`
	LocationType string            `json:"locationType,omitempty" mapstructure:"location_type,omitempty" desc:"Location type"`

	// Identity fields
	Name             string `json:"name,omitempty" mapstructure:"name,omitempty" desc:"Display name of the asset"`
	Icon             string `json:"icon,omitempty" mapstructure:"icon,omitempty" desc:"Icon identifier"`
	IsScaEnabled     *bool  `json:"isScaEnabled,omitempty" mapstructure:"is_sca_enabled,omitempty" desc:"Whether SCA is enabled"`
	IsSwsEnabled     *bool  `json:"isSwsEnabled,omitempty" mapstructure:"is_sws_enabled,omitempty" desc:"Whether SWS is enabled"`
	IsLaunchDisabled *bool  `json:"isLaunchDisabled,omitempty" mapstructure:"is_launch_disabled,omitempty" desc:"Whether launch is disabled"`

	// Additional properties
	CustomProperties     map[string]interface{} `json:"customProperties,omitempty" mapstructure:"custom_properties,omitempty" desc:"Custom properties of the asset"`
	ConnectionComponents []string               `json:"connectionComponents,omitempty" mapstructure:"connection_components,omitempty" desc:"Available connection components"`

	// Manual ZSP fields
	SelectedTokenOption string `json:"selectedTokenOption,omitempty" mapstructure:"selected_token_option,omitempty" desc:"Selected token option"`
	NetworkID           string `json:"networkId,omitempty" mapstructure:"network_id,omitempty" desc:"Network identifier"`
}
