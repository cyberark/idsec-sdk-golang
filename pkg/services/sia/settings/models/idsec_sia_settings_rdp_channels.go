package models

// IdsecSIASettingsRdpChannels represents the RDP channels configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) virtual
// channels in the Idsec SIA service. It defines whether the GFX (graphics) channel is
// enabled for RDP connections, controlling RemoteFX-style graphics acceleration.
type IdsecSIASettingsRdpChannels struct {
	GfxChannelEnabled *bool `json:"gfx_channel_enabled,omitempty" mapstructure:"gfx_channel_enabled,omitempty" flag:"gfx-channel-enabled" desc:"Indicates whether the GFX channel is enabled for RDP connections."`
}
