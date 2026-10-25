// Package federations provides the IDSEC Identity federations service, which manages SAML 2.0
// and OIDC identity provider federations and their global group mappings.
package federations

import (
	"errors"
	"reflect"
	"slices"
	"testing"

	federationsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/federations/models"
)

func boolPointer(value bool) *bool {
	return &value
}

// problemList renders each problem as "<attribute>[<index>].<field>: <summary>", so a test pins
// which check fired and where.
func problemList(err error) []string {
	got := []string{}
	var joined interface{ Unwrap() []error }
	if !errors.As(err, &joined) {
		return got
	}
	for _, e := range joined.Unwrap() {
		var problem *FederationSettingsError
		if !errors.As(e, &problem) {
			got = append(got, "not a FederationSettingsError: "+e.Error())
			continue
		}
		where := problem.Attribute
		if problem.Index >= 0 {
			where += "[" + string(rune('0'+problem.Index)) + "]"
		}
		if problem.Field != "" {
			where += "." + problem.Field
		}
		got = append(got, where+": "+problem.Summary)
		if !slices.Contains(problem.DependsOn, problem.Attribute) {
			got = append(got, where+": DependsOn does not list the attribute")
		}
	}
	slices.Sort(got)
	return got
}

func TestValidateFederationSettings(t *testing.T) {
	cloud := func(f federationsmodels.IdsecIdentityFederation) federationsmodels.IdsecIdentityFederation {
		f.MapUserDirectoryService = CloudDirectoryServiceUUID
		return f
	}
	mappings := []federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}}
	tests := []struct {
		name       string
		federation federationsmodels.IdsecIdentityFederation
		want       []string
	}{
		{name: "defaults", federation: federationsmodels.IdsecIdentityFederation{FederationType: "SAML 2.0", MapUsers: "Disabled", UserAgents: []string{"Any"}}},
		{name: "create users without Required mapping",
			federation: federationsmodels.IdsecIdentityFederation{MapUsers: "Optional", MapUserCreateIfNotFound: true},
			want:       []string{"map_user_create_if_not_found: User Creation Needs Required Mapping"}},
		{name: "OIDC create users without email scope",
			federation: federationsmodels.IdsecIdentityFederation{FederationType: "OIDC", MapUsers: "Required", MapUserCreateIfNotFound: true, OIDCScopes: []string{"openid"}},
			want:       []string{"oidc_scopes: Missing Email Scope"}},
		{name: "OIDC create users with email scope",
			federation: federationsmodels.IdsecIdentityFederation{FederationType: "OIDC", MapUsers: "Required", MapUserCreateIfNotFound: true, OIDCScopes: []string{"openid", "email"}}},
		{name: "SAML create users needs no scope",
			federation: federationsmodels.IdsecIdentityFederation{FederationType: "SAML 2.0", MapUsers: "Required", MapUserCreateIfNotFound: true}},
		{name: "ordered group mappings",
			federation: federationsmodels.IdsecIdentityFederation{GroupMappings: []federationsmodels.IdsecIdentityFederationGroupMapping{{AttributeValue: "b", GroupName: "B"}, {AttributeValue: "a", GroupName: "A"}, {AttributeValue: "a", GroupName: "B"}}}},
		{name: "duplicate group mapping",
			federation: federationsmodels.IdsecIdentityFederation{GroupMappings: []federationsmodels.IdsecIdentityFederationGroupMapping{{AttributeValue: "a", GroupName: "A"}, {AttributeValue: "a", GroupName: "A"}}},
			want:       []string{"group_mappings[1]: Duplicate Group Mapping"}},
		{name: "attribute mappings on the Cloud Directory with a sync option",
			federation: cloud(federationsmodels.IdsecIdentityFederation{MapUsers: "Required", MapUserSyncWithFedUser: true, AttributeMappings: mappings})},
		{name: "attribute mappings on another directory",
			federation: federationsmodels.IdsecIdentityFederation{MapUsers: "Required", MapUserSyncWithFedUser: true, MapUserDirectoryService: "other", AttributeMappings: mappings},
			want:       []string{"map_user_directory_service: Attribute Mappings Need The Cloud Directory"}},
		{name: "attribute mappings without a sync option",
			federation: cloud(federationsmodels.IdsecIdentityFederation{MapUsers: "Required", AttributeMappings: mappings}),
			want:       []string{"attribute_mappings: Attribute Mappings Are Not Applied"}},
		{name: "attribute mappings with Optional mapping",
			federation: cloud(federationsmodels.IdsecIdentityFederation{MapUsers: "Optional", AttributeMappings: mappings})},
		{name: "duplicate target",
			federation: cloud(federationsmodels.IdsecIdentityFederation{MapUsers: "Optional", AttributeMappings: append(slices.Clone(mappings), federationsmodels.IdsecIdentityFederationAttributeMapping{Target: "displayname", Source: "nickname"})}),
			want:       []string{"attribute_mappings[1].target: Duplicate Attribute Mapping"}},
		{name: "partial device types with Required mapping",
			federation: federationsmodels.IdsecIdentityFederation{MapUsers: "Required", DeviceTypes: []string{"iOS"}, UserAgents: []string{"Browser"}}},
		{name: "partial device types without Required mapping",
			federation: federationsmodels.IdsecIdentityFederation{MapUsers: "Disabled", DeviceTypes: []string{"Others"}, UserAgents: []string{"Any"}},
			want:       []string{"device_types: Device Routing Needs Required Mapping"}},
		{name: "mobile devices with any user agent",
			federation: federationsmodels.IdsecIdentityFederation{MapUsers: "Required", DeviceTypes: []string{"Android"}, UserAgents: []string{"Any"}},
			want:       []string{"user_agents: Unsupported User Agent For Mobile Devices"}},
		{name: "mobile devices with non-browser user agent",
			federation: federationsmodels.IdsecIdentityFederation{MapUsers: "Required", DeviceTypes: []string{"iOS"}, UserAgents: []string{"Browser", "NonBrowser"}},
			want:       []string{"user_agents: Unsupported User Agent For Mobile Devices"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			federation := tt.federation
			err := ValidateFederationSettings(&federation)
			if got := problemList(err); !slices.Equal(got, tt.want) {
				t.Errorf("problems = %q, want %q", got, tt.want)
			}
			if (err == nil) != (len(tt.want) == 0) {
				t.Errorf("error = %v, want one only when there are problems", err)
			}
		})
	}
}

func TestEffectiveCreateSettings(t *testing.T) {
	got := EffectiveCreateSettings(&federationsmodels.IdsecIdentityCreateFederation{FederationType: "SAML 2.0"})
	want := &federationsmodels.IdsecIdentityFederation{
		FederationType:         "SAML 2.0",
		MapUsers:               defaultMapUsers,
		MapUserSyncWithFedUser: defaultSyncWithFedUser,
		UserAgents:             []string{"Any"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("EffectiveCreateSettings() = %+v, want the defaults Create sends: %+v", got, want)
	}

	got = EffectiveCreateSettings(&federationsmodels.IdsecIdentityCreateFederation{
		FederationType:         "OIDC",
		MapUsers:               "Required",
		MapUserSyncWithFedUser: boolPointer(false),
		DeviceTypes:            []string{"Android", "iOS", "Others"},
		UserAgents:             []string{"Browser"},
	})
	if got.MapUsers != "Required" || got.MapUserSyncWithFedUser || got.DeviceTypes != nil || !slices.Equal(got.UserAgents, []string{"Browser"}) {
		t.Errorf("EffectiveCreateSettings() = %+v, want the request, with every device type stored as none", got)
	}
}

func TestEffectiveUpdateSettings(t *testing.T) {
	stored := &federationsmodels.IdsecIdentityFederation{
		FederationType:          "OIDC",
		OIDCScopes:              []string{"openid", "email"},
		MapUsers:                "Required",
		MapUserDirectoryService: CloudDirectoryServiceUUID,
		MapUserSyncWithFedUser:  true,
		MapUserCreateIfNotFound: true,
		AttributeMappings:       []federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}},
		DeviceTypes:             []string{"iOS"},
		UserAgents:              []string{"Browser"},
	}
	// Nothing set: the stored settings.
	if got := EffectiveUpdateSettings(stored, &federationsmodels.IdsecIdentityUpdateFederation{}); !reflect.DeepEqual(got, stored) {
		t.Errorf("EffectiveUpdateSettings() = %+v, want the stored settings %+v", got, stored)
	}
	// What is set replaces the stored value, and an empty list clears it.
	got := EffectiveUpdateSettings(stored, &federationsmodels.IdsecIdentityUpdateFederation{
		MapUsers:          "Optional",
		AttributeMappings: &[]federationsmodels.IdsecIdentityFederationAttributeMapping{},
		UserAgents:        &[]string{},
	})
	if got.MapUsers != "Optional" || len(got.AttributeMappings) != 0 || !slices.Equal(got.UserAgents, []string{"Any"}) || !slices.Equal(got.DeviceTypes, []string{"iOS"}) {
		t.Errorf("EffectiveUpdateSettings() = %+v, want the request over the stored settings", got)
	}
}

// TestCreateRejectsSettingsTheServerRefuses: a mobile federation with user_agents left unset is
// stored with Any, which the server refuses, so Create fails before anything is posted.
func TestCreateRejectsSettingsTheServerRefuses(t *testing.T) {
	server := newFakeServer(nil)
	service := newTestService(t, server)
	_, err := service.Create(&federationsmodels.IdsecIdentityCreateFederation{
		FederationName:  "Mobile",
		FederationType:  "SAML 2.0",
		SAMLMetadataURL: "https://idp.example.com/metadata",
		MapUsers:        "Required",
		DeviceTypes:     []string{"iOS"},
	})
	var problem *FederationSettingsError
	if !errors.As(err, &problem) || problem.Attribute != "user_agents" {
		t.Fatalf("Create() error = %v, want a user_agents FederationSettingsError", err)
	}
	if len(server.calls) != 0 {
		t.Errorf("Create() called the server %v, want no call", server.calls)
	}
}

// TestUpdateChecksTheMergedSettings: the request alone is valid, but with the stored settings it
// would leave attribute mappings on a federation that no longer syncs or creates users.
func TestUpdateChecksTheMergedSettings(t *testing.T) {
	server := newFakeServer(map[string]string{
		readFederationURL: `{"success": true, "Result": ` + oidcFederationJSON + `}`,
	})
	service := newTestService(t, server)
	_, err := service.Update(&federationsmodels.IdsecIdentityUpdateFederation{
		FederationUUID:          "fed-1",
		FederationName:          "Okta",
		Active:                  true,
		MapUsers:                "Required",
		MapUserDirectoryService: CloudDirectoryServiceUUID,
		MapUserSyncWithFedUser:  boolPointer(false),
		AttributeMappings:       &[]federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}},
	})
	var problem *FederationSettingsError
	if !errors.As(err, &problem) || problem.Attribute != "attribute_mappings" {
		t.Fatalf("Update() error = %v, want an attribute_mappings FederationSettingsError", err)
	}
	if server.calls[updateFederationURL] != 0 {
		t.Error("Update() posted settings the server would drop")
	}
}

// TestUpdateIgnoresProblemsItDoesNotTouch: attribute mappings stored on a federation with another
// directory are the server's to drop, and do not block an update that sets neither.
func TestUpdateIgnoresProblemsItDoesNotTouch(t *testing.T) {
	stored := &federationsmodels.IdsecIdentityFederation{
		FederationType: "SAML 2.0", MapUsers: "Required", MapUserSyncWithFedUser: true, UserAgents: []string{"Any"},
		AttributeMappings: []federationsmodels.IdsecIdentityFederationAttributeMapping{{Target: "DisplayName", Source: "name"}},
	}
	if err := ValidateUpdateFederationSettings(stored, &federationsmodels.IdsecIdentityUpdateFederation{FederationName: "renamed"}); err != nil {
		t.Errorf("an update that touches neither failed: %v", err)
	}
	err := ValidateUpdateFederationSettings(stored, &federationsmodels.IdsecIdentityUpdateFederation{MapUserDirectoryService: "other"})
	if got := problemList(err); !slices.Equal(got, []string{"map_user_directory_service: Attribute Mappings Need The Cloud Directory"}) {
		t.Errorf("an update that sets the directory: problems = %q", got)
	}
}

// TestUpdateLeavesAStoredCreateOptionAlone: the portal can store map_user_create_if_not_found with
// a mode other than Required. An update that leaves it as it is, or resends the stored value as the
// Terraform provider does, must not fail on it; one that turns it on must.
func TestUpdateLeavesAStoredCreateOptionAlone(t *testing.T) {
	stored := &federationsmodels.IdsecIdentityFederation{FederationType: "SAML 2.0", MapUsers: "Optional", MapUserCreateIfNotFound: true, UserAgents: []string{"Any"}}
	for name, arg := range map[string]*federationsmodels.IdsecIdentityUpdateFederation{
		"unset":  {FederationName: "renamed"},
		"resent": {FederationName: "renamed", MapUsers: "Optional", MapUserCreateIfNotFound: boolPointer(true)},
	} {
		if err := ValidateUpdateFederationSettings(stored, arg); err != nil {
			t.Errorf("%s: an update that does not change the option failed: %v", name, err)
		}
	}
	stored.MapUserCreateIfNotFound = false
	err := ValidateUpdateFederationSettings(stored, &federationsmodels.IdsecIdentityUpdateFederation{MapUserCreateIfNotFound: boolPointer(true)})
	if got := problemList(err); !slices.Equal(got, []string{"map_user_create_if_not_found: User Creation Needs Required Mapping"}) {
		t.Errorf("an update that turns the option on: problems = %q", got)
	}

	// Leaving Required mode with the option on, the option itself unchanged: the server would
	// silently stop creating users.
	stored = &federationsmodels.IdsecIdentityFederation{FederationType: "SAML 2.0", MapUsers: "Required", MapUserCreateIfNotFound: true, UserAgents: []string{"Any"}}
	err = ValidateUpdateFederationSettings(stored, &federationsmodels.IdsecIdentityUpdateFederation{MapUsers: "Optional", MapUserCreateIfNotFound: boolPointer(true)})
	if got := problemList(err); !slices.Equal(got, []string{"map_user_create_if_not_found: User Creation Needs Required Mapping"}) {
		t.Errorf("an update that leaves Required mode: problems = %q", got)
	}
}
