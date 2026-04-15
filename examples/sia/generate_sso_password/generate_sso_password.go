package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
)

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	ispAuthInterface := auth.NewIdsecISPAuth(false)
	_, err := ispAuthInterface.Authenticate(
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

	// Type assert to get concrete ISP auth type
	ispAuth := ispAuthInterface.(*auth.IdsecISPAuth)

	// Create an ISP base service with the authenticator
	// The SSO service shares this base service for ISP client and telemetry
	ispBaseService, err := services.NewIdsecISPBaseService(
		ispAuth,
		"dpa",
		".",
		"",
		func(client *common.IdsecClient) error {
			return isp.RefreshClient(client, ispAuth)
		},
	)
	if err != nil {
		panic(err)
	}

	// Create an SSO service from the ISP base service
	ssoService, err := sso.NewIdsecSIASSOService(ispBaseService)
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
