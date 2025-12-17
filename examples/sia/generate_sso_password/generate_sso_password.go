package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	ispAuth := auth.NewIdsecISPAuth(false)
	_, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           "user@cyberark.cloud.12345",
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: os.Getenv("IDSEC_SECRET"),
		},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}

	// Create an SSO service from the authenticator above
	ssoService, err := sso.NewIdsecSIASSOService(ispAuth)
	if err != nil {
		panic(err)
	}

	// Generate a short-lived password for DB
	ssoPassword, err := ssoService.ShortLivedPassword(
		&ssomodels.IdsecSIASSOGetShortLivedPassword{},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssoPassword)

	// Generate a short-lived password for RDP
	ssoPassword, err = ssoService.ShortLivedPassword(
		&ssomodels.IdsecSIASSOGetShortLivedPassword{
			Service: "DPA-RDP",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("%s\n", ssoPassword)
}
