// Package models provides data structures and types for the IDSEC SDK.
// This package contains profile and configuration models used to represent
// various IDSEC SDK entities and their properties for authentication and
// configuration management.
package models

import (
	"encoding/json"

	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

// IdsecProfile represents a profile configuration for the IDSEC SDK.
// This structure contains the essential information needed to define a profile
// including its name, description, and associated authentication profiles.
// It supports JSON marshaling/unmarshaling with custom handling for auth profiles
// to ensure proper type safety during deserialization.
//
// The struct fields include validation tags, mapstructure tags for configuration
// mapping, and flag tags for command-line interface integration.
//
// Example usage:
//
//	profile := &IdsecProfile{
//		ProfileName:        "my-profile",
//		ProfileDescription: "Development environment profile",
//		AuthProfiles:       make(map[string]*auth.IdsecAuthProfile),
//	}
type IdsecProfile struct {
	ProfileName        string                            `json:"profile_name" mapstructure:"profile_name" validate:"required" flag:"profile-name" desc:"The name of the profile to use"`
	ProfileDescription string                            `json:"profile_description" mapstructure:"profile_description" validate:"required" flag:"profile-description" desc:"Profile Description"`
	AuthProfiles       map[string]*auth.IdsecAuthProfile `json:"auth_profiles" mapstructure:"auth_profile" validate:"required" flag:"-"`
}

// UnmarshalJSON implements the json.Unmarshaler interface for IdsecProfile.
// It performs custom JSON unmarshaling to properly handle the AuthProfiles field
// which contains a map of authentication profiles that need special type handling.
//
// The method uses an auxiliary struct with json.RawMessage to defer the unmarshaling
// of individual auth profiles, allowing for proper type conversion from the raw
// JSON data to the specific IdsecAuthProfile type.
//
// Parameters:
//   - data: JSON byte data containing the profile information to unmarshal
//
// Returns:
//   - error: nil if unmarshaling succeeds, otherwise an error describing the failure
//
// Example JSON input:
//
//	{
//		"profile_name": "my-profile",
//		"profile_description": "Development profile",
//		"auth_profiles": {
//			"default": {
//				"auth_type": "service_user",
//				"username": "user@example.com"
//			}
//		}
//	}
func (p *IdsecProfile) UnmarshalJSON(data []byte) error {
	type Alias IdsecProfile
	aux := &struct {
		AuthProfiles map[string]json.RawMessage `json:"auth_profiles"`
		*Alias
	}{
		Alias: (*Alias)(p),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	p.AuthProfiles = make(map[string]*auth.IdsecAuthProfile)
	for key, rawMessage := range aux.AuthProfiles {
		var authProfile auth.IdsecAuthProfile
		if err := json.Unmarshal(rawMessage, &authProfile); err != nil {
			return err
		}
		p.AuthProfiles[key] = &authProfile
	}

	return nil
}
