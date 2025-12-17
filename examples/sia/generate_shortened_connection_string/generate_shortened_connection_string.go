package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring"
	shortenedconnectionstringmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/shortenedconnectionstring/models"

	"os"
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

	// Generate a shortened connection string
	shortenedConnectionStringService, err := shortenedconnectionstring.NewIdsecSIAShortenedConnectionStringService(ispAuth)
	if err != nil {
		panic(err)
	}
	shortenedConnectionString, err := shortenedConnectionStringService.Generate(
		&shortenedconnectionstringmodels.IdsecSIAGenerateShortenedConnectionString{
			RawConnectionString: "jack.sparrow@caribbean.airlines#caribbean-airlines@the.black.pearl.com103639",
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Shortened Connection String: %s\n", shortenedConnectionString.ShortenedConnectionString)
}
