package auth

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"slices"
)

var (
	// SupportedAuthenticatorsList is a list of supported authenticators.
	SupportedAuthenticatorsList = []IdsecAuth{
		NewIdsecISPAuth(true),
	}

	// SupportedAuthenticators is a map of supported authenticators.
	SupportedAuthenticators = func() map[string]IdsecAuth {
		authenticators := make(map[string]IdsecAuth)
		for _, auth := range SupportedAuthenticatorsList {
			authenticators[auth.AuthenticatorName()] = auth
		}
		return authenticators
	}()

	// SupportedAuthMethods is a list of supported authentication methods.
	SupportedAuthMethods = func() []auth.IdsecAuthMethod {
		authMethods := make([]auth.IdsecAuthMethod, 0)
		for _, auth := range SupportedAuthenticatorsList {
			for _, method := range auth.SupportedAuthMethods() {
				if !slices.Contains(authMethods, method) {
					authMethods = append(authMethods, method)
				}
			}
		}
		return authMethods
	}()
)
