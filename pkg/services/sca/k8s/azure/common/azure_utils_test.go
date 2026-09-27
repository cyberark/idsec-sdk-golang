package common

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCloudUserMatches(t *testing.T) {
	cases := []struct {
		name          string
		cloudUserName string
		azure         JWTIdentity
		want          bool
	}{
		{
			name:          "upn match",
			cloudUserName: "au_team_apps_k8s_cli_2@Contoso.onmicrosoft.com",
			azure:         JWTIdentity{UPN: "au_team_apps_k8s_cli_2@contoso.onmicrosoft.com"},
			want:          true,
		},
		{
			name:          "falls back to email when upn differs",
			cloudUserName: "rupert@test-acme.com",
			azure:         JWTIdentity{UPN: "someone-else@tenant.com", Email: "rupert@test-acme.com"},
			want:          true,
		},
		{
			name:          "guest upn normalized to home tenant",
			cloudUserName: "rupert@acme.com",
			azure:         JWTIdentity{UPN: "rupert_acme.com#EXT#@test-acme.onmicrosoft.com"},
			want:          true,
		},
		{
			name:          "external guest resolved to home domain",
			cloudUserName: "jane.doe@homecorp.com",
			azure:         JWTIdentity{UPN: "jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com"},
			want:          true,
		},
		{
			name:          "external guest resolved to resource tenant domain",
			cloudUserName: "jane.doe@Contoso.onmicrosoft.com",
			azure:         JWTIdentity{UPN: "jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com"},
			want:          true,
		},
		{
			// Guests carry the home address on email, not upn.
			name:          "external guest matched via email claim",
			cloudUserName: "jane.doe@homecorp.com",
			azure: JWTIdentity{
				UPN:   "jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com",
				Email: "jane.doe@homecorp.com",
			},
			want: true,
		},
		{
			// Both sides normalized, so it also matches if Elevate ever returns the guest form.
			name:          "guest form on both sides",
			cloudUserName: "jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com",
			azure:         JWTIdentity{UPN: "jane.doe_homecorp.com#EXT#@contoso.onmicrosoft.com"},
			want:          true,
		},
		{
			name:          "guest marker is case insensitive",
			cloudUserName: "jane.doe@homecorp.com",
			azure:         JWTIdentity{UPN: "jane.doe_homecorp.com#ext#@Contoso.onmicrosoft.com"},
			want:          true,
		},
		{
			name:          "different guest from same home domain",
			cloudUserName: "jane.doe@homecorp.com",
			azure:         JWTIdentity{UPN: "someone.else_homecorp.com#EXT#@Contoso.onmicrosoft.com"},
			want:          false,
		},
		{
			name:          "home domain folded into upn without guest marker",
			cloudUserName: "team_apps_k8s@Contoso.onmicrosoft.com",
			azure:         JWTIdentity{UPN: "team_apps_k8s_homecorp.com@Contoso.onmicrosoft.com"},
			want:          true,
		},
		{
			// Splitting on a non-domain suffix would wrongly equate two real users.
			name:          "underscored name must not collide with a shorter account",
			cloudUserName: "team_apps@Contoso.onmicrosoft.com",
			azure:         JWTIdentity{UPN: "team_apps_k8s@Contoso.onmicrosoft.com"},
			want:          false,
		},
		{
			name:          "mapped account is not the login account",
			cloudUserName: "rupert@test-acme.com",
			azure:         JWTIdentity{UPN: "rupert@acme.com", Email: "rupert@acme.com"},
			want:          false,
		},
		{
			// Display names are never comparable — only addressable forms are.
			name:          "display name never matches",
			cloudUserName: "Jane Doe",
			azure: JWTIdentity{
				UPN:   "jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com",
				Email: "jane.doe@homecorp.com",
			},
			want: false,
		},
		{
			// Email is the last stage; absent means the comparison fails.
			name:          "no email claim and upn differs",
			cloudUserName: "team_apps_k8s@Contoso.onmicrosoft.com",
			azure:         JWTIdentity{UPN: "someone.else@Contoso.onmicrosoft.com"},
			want:          false,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, CloudUserMatches(c.cloudUserName, c.azure))
		})
	}
}

func TestUPNVariants(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "guest yields raw, home and resource tenant forms",
			in:   "jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com",
			want: []string{
				"jane.doe_homecorp.com#EXT#@Contoso.onmicrosoft.com",
				"jane.doe@homecorp.com",
				"jane.doe@Contoso.onmicrosoft.com",
			},
		},
		{
			// Only the final underscore separates the appended home domain.
			name: "underscore in home local part",
			in:   "first_last_acme.com#EXT#@tenant.onmicrosoft.com",
			want: []string{
				"first_last_acme.com#EXT#@tenant.onmicrosoft.com",
				"first_last@acme.com",
				"first_last@tenant.onmicrosoft.com",
			},
		},
		{
			// Same folding, but without the #EXT# marker.
			name: "external account without the guest marker",
			in:   "team_apps_k8s_homecorp.com@Contoso.onmicrosoft.com",
			want: []string{
				"team_apps_k8s_homecorp.com@Contoso.onmicrosoft.com",
				"team_apps_k8s@homecorp.com",
				"team_apps_k8s@Contoso.onmicrosoft.com",
			},
		},
		{
			// "k8s" is not a domain, so this must not split into team_apps@...
			name: "ordinary underscored name is not split",
			in:   "team_apps_k8s@Contoso.onmicrosoft.com",
			want: []string{"team_apps_k8s@Contoso.onmicrosoft.com"},
		},
		{
			name: "trailing numeric segment is not a domain",
			in:   "au_team_apps_k8s_cli_2@Contoso.onmicrosoft.com",
			want: []string{"au_team_apps_k8s_cli_2@Contoso.onmicrosoft.com"},
		},
		{
			name: "plain upn yields itself",
			in:   "  rupert@acme.com  ",
			want: []string{"rupert@acme.com"},
		},
		{
			name: "guest marker without separator is left alone",
			in:   "nounderscore#EXT#@tenant.onmicrosoft.com",
			want: []string{"nounderscore#EXT#@tenant.onmicrosoft.com"},
		},
		{
			name: "empty",
			in:   "   ",
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			require.Equal(t, c.want, UPNVariants(c.in))
		})
	}
}
