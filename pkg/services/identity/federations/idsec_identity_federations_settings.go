// Package federations provides the IDSEC Identity federations service, which manages SAML 2.0
// and OIDC identity provider federations and their global group mappings.
package federations

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	federationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/models"
)

// CloudDirectoryServiceUUID is the CyberArk Cloud Directory, the only directory the server stores
// attribute mappings for.
const CloudDirectoryServiceUUID = "09B9A9B0-6CE8-465F-AB03-65766D33B05E"

const mapUsersRequired = "Required"

// FederationSettingsError is one combination of federation settings that the server rejects, or
// accepts and then silently ignores or rewrites. ValidateFederationSettings joins one per problem.
//
// It names where the problem is, so a caller can point at it: the Terraform provider turns it into
// an error on that attribute at plan time.
type FederationSettingsError struct {
	// Attribute is the attribute the problem is reported on, by its mapstructure name.
	Attribute string
	// Index is the position of the offending entry in the Attribute list, or -1 for the attribute
	// as a whole.
	Index int
	// Field is the field of that entry the problem is on, such as "target", or "" for the entry.
	Field string
	// DependsOn lists every attribute the check read, Attribute included. A caller that does not
	// know all of them yet, such as a Terraform plan with values computed during apply, cannot tell
	// whether the problem stands.
	DependsOn []string
	// Summary is a short title, and Detail says what to change.
	Summary string
	Detail  string
}

// Error implements error.
func (e *FederationSettingsError) Error() string {
	return fmt.Sprintf("%s: %s", e.Summary, e.Detail)
}

// ValidateFederationSettings checks a federation's effective settings, after stored values and
// server defaults are applied, for combinations the server rejects or silently rewrites. The
// returned error joins one *FederationSettingsError per problem, or is nil.
//
// These rules span several attributes, so they cannot be validate tags: an update only carries the
// attributes it changes. Create and Update check them through ValidateCreateFederationSettings and
// ValidateUpdateFederationSettings, which the Terraform provider also calls at plan time, so a plan
// and its apply agree.
func ValidateFederationSettings(federation *federationsmodels.IdsecIdentityFederation) error {
	problems := federationSettingsProblems(federation)
	joined := make([]error, 0, len(problems))
	for _, problem := range problems {
		joined = append(joined, problem)
	}
	return errors.Join(joined...)
}

func federationSettingsProblems(f *federationsmodels.IdsecIdentityFederation) []*FederationSettingsError {
	var problems []*FederationSettingsError
	add := func(problem FederationSettingsError) {
		problems = append(problems, &problem)
	}
	required := f.MapUsers == mapUsersRequired

	// The server ignores the option in any other mode.
	if f.MapUserCreateIfNotFound && !required {
		add(FederationSettingsError{
			Attribute: "map_user_create_if_not_found", Index: -1,
			DependsOn: []string{"map_user_create_if_not_found", "map_users"},
			Summary:   "User Creation Needs Required Mapping",
			Detail:    `map_user_create_if_not_found only takes effect when map_users is "Required".`,
		})
	}
	if f.FederationType == federationTypeOIDC && f.MapUserCreateIfNotFound && required && !slices.Contains(f.OIDCScopes, "email") {
		add(FederationSettingsError{
			Attribute: "oidc_scopes", Index: -1,
			DependsOn: []string{"federation_type", "map_user_create_if_not_found", "map_users", "oidc_scopes"},
			Summary:   "Missing Email Scope",
			Detail:    `oidc_scopes must include "email" for an OIDC federation to create users that are not found.`,
		})
	}

	// The server collapses duplicate group mappings, so the list would read back shorter.
	seenGroups := map[federationsmodels.IdsecIdentityFederationGroupMapping]bool{}
	for i, mapping := range f.GroupMappings {
		if seenGroups[mapping] {
			add(FederationSettingsError{
				Attribute: "group_mappings", Index: i, DependsOn: []string{"group_mappings"},
				Summary: "Duplicate Group Mapping",
				Detail:  fmt.Sprintf("%q is already mapped to %q: the server keeps one of them.", mapping.AttributeValue, mapping.GroupName),
			})
		}
		seenGroups[mapping] = true
	}

	if len(f.AttributeMappings) > 0 {
		seenTargets := map[string]bool{}
		for i, mapping := range f.AttributeMappings {
			target := strings.ToLower(mapping.Target)
			if seenTargets[target] {
				add(FederationSettingsError{
					Attribute: "attribute_mappings", Index: i, Field: "target", DependsOn: []string{"attribute_mappings"},
					Summary: "Duplicate Attribute Mapping",
					Detail:  fmt.Sprintf("%q is mapped more than once.", mapping.Target),
				})
			}
			seenTargets[target] = true
		}
		// The server drops attribute mappings unless it provisions the users into the Cloud
		// Directory (FederationController.ValidateAndPrepareAttributeMapping).
		switch {
		case !strings.EqualFold(f.MapUserDirectoryService, CloudDirectoryServiceUUID):
			add(FederationSettingsError{
				Attribute: "map_user_directory_service", Index: -1,
				DependsOn: []string{"attribute_mappings", "map_user_directory_service"},
				Summary:   "Attribute Mappings Need The Cloud Directory",
				Detail:    fmt.Sprintf("attribute_mappings are only stored when map_user_directory_service is the CyberArk Cloud Directory (%s).", CloudDirectoryServiceUUID),
			})
		case f.MapUsers != "Optional" && !f.MapUserSyncWithFedUser && !f.MapUserSyncWithCloudUser && !f.MapUserCreateIfNotFound:
			add(FederationSettingsError{
				Attribute: "attribute_mappings", Index: -1,
				DependsOn: []string{"attribute_mappings", "map_users", "map_user_sync_with_federated_user", "map_user_sync_with_cloud_user", "map_user_create_if_not_found"},
				Summary:   "Attribute Mappings Are Not Applied",
				Detail: `attribute_mappings are only stored when map_users is "Optional", or one of map_user_sync_with_federated_user, ` +
					"map_user_sync_with_cloud_user or map_user_create_if_not_found is true.",
			})
		}
	}

	// Routing (FederationController.ParseCreateUpdateFederationParameters and
	// FederationHelper.SetUserAgents). No device types means every device type, and no user agent
	// is stored as Any, which is why a mobile federation that leaves user_agents unset is refused.
	if len(f.DeviceTypes) > 0 && !required {
		add(FederationSettingsError{
			Attribute: "device_types", Index: -1, DependsOn: []string{"device_types", "map_users"},
			Summary: "Device Routing Needs Required Mapping",
			Detail:  `Routing by a subset of device types needs map_users to be "Required".`,
		})
	}
	mobile := slices.Contains(f.DeviceTypes, "iOS") || slices.Contains(f.DeviceTypes, "Android")
	if mobile && (slices.Contains(f.UserAgents, "Any") || slices.Contains(f.UserAgents, "NonBrowser")) {
		add(FederationSettingsError{
			Attribute: "user_agents", Index: -1, DependsOn: []string{"device_types", "user_agents"},
			Summary: "Unsupported User Agent For Mobile Devices",
			Detail:  `Routing iOS or Android devices needs user_agents to be ["Browser"]; an unset user_agents is stored as ["Any"].`,
		})
	}
	return problems
}

// EffectiveCreateSettings returns the settings a create request results in: the request, with the
// defaults Create sends for what it leaves unset, and the ones the server applies. Only the
// settings ValidateFederationSettings checks are filled.
func EffectiveCreateSettings(arg *federationsmodels.IdsecIdentityCreateFederation) *federationsmodels.IdsecIdentityFederation {
	federation := &federationsmodels.IdsecIdentityFederation{
		FederationType:           arg.FederationType,
		OIDCScopes:               arg.OIDCScopes,
		GroupMappings:            arg.GroupMappings,
		MapUsers:                 valueOr(arg.MapUsers, defaultMapUsers),
		MapUserDirectoryService:  arg.MapUserDirectoryService,
		MapUserSyncWithFedUser:   boolOr(arg.MapUserSyncWithFedUser, defaultSyncWithFedUser),
		MapUserSyncWithCloudUser: boolOr(arg.MapUserSyncWithCloudUser, false),
		MapUserCreateIfNotFound:  boolOr(arg.MapUserCreateIfNotFound, false),
		AttributeMappings:        arg.AttributeMappings,
	}
	setRouting(federation, arg.DeviceTypes, arg.UserAgents)
	return federation
}

// EffectiveUpdateSettings returns the settings an update results in: the stored federation, as Get
// returns it, with the fields the request sets laid over it, the way Update resends the stored
// value of every field it leaves unset. Only the settings ValidateFederationSettings checks are
// filled.
func EffectiveUpdateSettings(stored *federationsmodels.IdsecIdentityFederation, arg *federationsmodels.IdsecIdentityUpdateFederation) *federationsmodels.IdsecIdentityFederation {
	federation := &federationsmodels.IdsecIdentityFederation{
		FederationType:           stored.FederationType,
		OIDCScopes:               pointerOr(arg.OIDCScopes, stored.OIDCScopes),
		GroupMappings:            pointerOr(arg.GroupMappings, stored.GroupMappings),
		MapUsers:                 valueOr(arg.MapUsers, stored.MapUsers),
		MapUserDirectoryService:  valueOr(arg.MapUserDirectoryService, stored.MapUserDirectoryService),
		MapUserSyncWithFedUser:   boolOr(arg.MapUserSyncWithFedUser, stored.MapUserSyncWithFedUser),
		MapUserSyncWithCloudUser: boolOr(arg.MapUserSyncWithCloudUser, stored.MapUserSyncWithCloudUser),
		MapUserCreateIfNotFound:  boolOr(arg.MapUserCreateIfNotFound, stored.MapUserCreateIfNotFound),
		AttributeMappings:        pointerOr(arg.AttributeMappings, stored.AttributeMappings),
	}
	setRouting(federation, pointerOr(arg.DeviceTypes, stored.DeviceTypes), pointerOr(arg.UserAgents, stored.UserAgents))
	return federation
}

// setRouting stores the routing lists the way the server does: every device type selected is the
// same as none, and no user agent is Any.
func setRouting(federation *federationsmodels.IdsecIdentityFederation, deviceTypes, userAgents []string) {
	federation.DeviceTypes = deviceTypes
	if len(deviceTypes) >= 3 {
		federation.DeviceTypes = nil
	}
	federation.UserAgents = userAgents
	if len(userAgents) == 0 {
		federation.UserAgents = []string{"Any"}
	}
}

func boolOr(value *bool, fallback bool) bool {
	if value == nil {
		return fallback
	}
	return *value
}

func pointerOr[T any](value *[]T, fallback []T) []T {
	if value == nil {
		return fallback
	}
	return *value
}

// ValidateCreateFederationSettings checks the settings a create request would store. Create calls
// it before posting.
func ValidateCreateFederationSettings(arg *federationsmodels.IdsecIdentityCreateFederation) error {
	return ValidateFederationSettings(EffectiveCreateSettings(arg))
}

// ValidateUpdateFederationSettings checks the settings an update request would store, given the
// federation as Get returns it. Update calls it before posting. It reports the problems the
// update has a hand in: those depending on at least one attribute the request changes. A problem
// made only of stored values was accepted by the server already, and refusing an unrelated update
// over it would leave the federation no better. That is also what keeps a federation the portal
// stored with map_user_create_if_not_found on in another mode updatable, until an update changes
// the option or the mode.
//
// Changes, not sets: the Terraform provider resends the stored value of every attribute the
// configuration leaves alone, so a value the request sets to what is stored has not been chosen.
func ValidateUpdateFederationSettings(stored *federationsmodels.IdsecIdentityFederation, arg *federationsmodels.IdsecIdentityUpdateFederation) error {
	effective := EffectiveUpdateSettings(stored, arg)
	changed := func(attribute string) bool { return settingChanged(stored, effective, attribute) }
	var kept []error
	for _, problem := range federationSettingsProblems(effective) {
		if !slices.ContainsFunc(problem.DependsOn, changed) {
			continue
		}
		kept = append(kept, problem)
	}
	return errors.Join(kept...)
}

// settingChanged reports whether an attribute ValidateFederationSettings reads differs between
// two settings. The routing lists and the scopes are sets, so their order does not count.
func settingChanged(before, after *federationsmodels.IdsecIdentityFederation, attribute string) bool {
	switch attribute {
	case "map_users":
		return before.MapUsers != after.MapUsers
	case "map_user_directory_service":
		return !strings.EqualFold(before.MapUserDirectoryService, after.MapUserDirectoryService)
	case "map_user_sync_with_federated_user":
		return before.MapUserSyncWithFedUser != after.MapUserSyncWithFedUser
	case "map_user_sync_with_cloud_user":
		return before.MapUserSyncWithCloudUser != after.MapUserSyncWithCloudUser
	case "map_user_create_if_not_found":
		return before.MapUserCreateIfNotFound != after.MapUserCreateIfNotFound
	case "oidc_scopes":
		return !sameSet(before.OIDCScopes, after.OIDCScopes)
	case "group_mappings":
		return !slices.Equal(before.GroupMappings, after.GroupMappings)
	case "attribute_mappings":
		return !slices.Equal(before.AttributeMappings, after.AttributeMappings)
	case "device_types":
		return !sameSet(before.DeviceTypes, after.DeviceTypes)
	case "user_agents":
		return !sameSet(before.UserAgents, after.UserAgents)
	}
	// federation_type cannot change.
	return false
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(slices.Compact(a), slices.Compact(b))
}
