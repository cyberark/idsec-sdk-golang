package main

import (
	"fmt"

	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/identity"
	authprofilesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/identity/authprofiles/models"
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

	// Create auth profile
	identityAPI, err := identity.NewIdsecIdentityAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	authProfile, err := identityAPI.AuthProfiles().Create(&authprofilesmodels.IdsecIdentityCreateAuthProfile{
		AuthProfileName:   "My Auth Profile",
		FirstChallenges:   []string{"UP"},
		SecondChallenges:  []string{"EMAIL"},
		DurationInMinutes: 60,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Auth Profile created: %v\n", authProfile)
}
