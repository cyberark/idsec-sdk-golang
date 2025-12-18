package models

// IdsecSIASettingsRdpKeyboardLayout represents the RDP keyboard layout configuration for SIA settings.
//
// This model contains configuration options for Remote Desktop Protocol (RDP) keyboard layout
// settings in the Idsec SIA service. It defines the keyboard layout that should be used
// during RDP sessions, allowing customization of input behavior based on regional
// or user preferences for different keyboard mappings.
type IdsecSIASettingsRdpKeyboardLayout struct {
	Layout *string `json:"layout,omitempty" mapstructure:"layout,omitempty" flag:"layout" desc:"The keyboard layout for RDP sessions."`
}
