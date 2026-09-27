// Package common holds Azure identity helpers shared by the SCA k8s flows.
// It is deliberately free of JWT and cloud SDK dependencies so the matching
// rules can be reasoned about and tested in isolation.
package common

import "strings"

// GuestUPNMarker separates the folded home address from the tenant domain in an
// Entra B2B guest UPN: "<user>_<homedomain>#EXT#@<tenant>".
const GuestUPNMarker = "#EXT#@"

// JWTIdentity is the identity carried by an Azure access token.
type JWTIdentity struct {
	UPN   string
	Email string
}

// Name returns the identity's most addressable form for diagnostics, preferring
// the UPN. Empty when the token carried neither claim.
func (i JWTIdentity) Name() string {
	if upn := strings.TrimSpace(i.UPN); upn != "" {
		return upn
	}
	return strings.TrimSpace(i.Email)
}

// CloudUserMatches resolves the Elevate cloudUserName against an az token
// identity in three widening stages: the UPN as reported, then the folded
// identity variants of both, then the email claim — an external account carries
// its home address on email rather than upn.
func CloudUserMatches(cloudUserName string, identity JWTIdentity) bool {
	cloudUserName = strings.TrimSpace(cloudUserName)
	if cloudUserName == "" {
		return false
	}

	if strings.EqualFold(cloudUserName, strings.TrimSpace(identity.UPN)) {
		return true
	}
	if IdentitiesShareVariant(cloudUserName, identity.UPN) {
		return true
	}
	return IdentitiesShareVariant(cloudUserName, identity.Email)
}

// IdentitiesShareVariant reports whether two identities resolve to a common
// form once each is expanded by UPNVariants.
func IdentitiesShareVariant(left, right string) bool {
	if strings.TrimSpace(left) == "" || strings.TrimSpace(right) == "" {
		return false
	}
	seen := make(map[string]struct{})
	for _, variant := range UPNVariants(left) {
		seen[strings.ToLower(variant)] = struct{}{}
	}
	for _, variant := range UPNVariants(right) {
		if _, ok := seen[strings.ToLower(variant)]; ok {
			return true
		}
	}
	return false
}

// UPNVariants returns the comparable forms of an Entra identity. An external
// account carries its home address folded into the local part with the "@"
// replaced by "_", either as "<user>_<homedomain>#EXT#@<tenant>" or as a plain
// "<user>_<homedomain>@<tenant>". That can legitimately be read as either
// "<user>@<homedomain>" or "<user>@<tenant>", so both accompany the raw value.
func UPNVariants(value string) []string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	variants := []string{value}

	local, tenantDomain := splitUPN(value)
	if local == "" || tenantDomain == "" {
		return variants
	}

	// The last underscore is the folded "@" — home local parts may contain
	// others. Requiring a dot in the suffix keeps ordinary underscored names
	// such as "team_apps_k8s" from being split into a different user.
	sep := strings.LastIndex(local, "_")
	if sep < 0 {
		return variants
	}
	user, homeDomain := local[:sep], local[sep+1:]
	if user == "" || !strings.Contains(homeDomain, ".") {
		return variants
	}
	return append(variants, user+"@"+homeDomain, user+"@"+tenantDomain)
}

// splitUPN separates the local part from the tenant domain, accepting both the
// B2B guest form "<local>#EXT#@<tenant>" and a plain "<local>@<tenant>".
func splitUPN(value string) (local, tenantDomain string) {
	if idx := strings.Index(strings.ToUpper(value), GuestUPNMarker); idx >= 0 {
		return value[:idx], value[idx+len(GuestUPNMarker):]
	}
	at := strings.LastIndex(value, "@")
	if at < 0 {
		return "", ""
	}
	return value[:at], value[at+1:]
}
