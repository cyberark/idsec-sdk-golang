// Package models provides shared request/input structures for SCA elevate operations.
package models

// IdsecSCAElevateErrorInfo is present in a result when the user is not eligible
// to access the requested target. Service-specific result models embed it as the
// per-target failure payload for partial-success elevate responses.
type IdsecSCAElevateErrorInfo struct {
	Code        string `json:"code" mapstructure:"code" desc:"Error code returned for the elevate failure"`
	Message     string `json:"message" mapstructure:"message" desc:"Short human-readable error message"`
	Description string `json:"description" mapstructure:"description" desc:"Detailed explanation of why elevate failed"`
	Link        string `json:"link,omitempty" mapstructure:"link,omitempty" desc:"Optional troubleshooting documentation URL"`
}
