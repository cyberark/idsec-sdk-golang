package main

import (
	"fmt"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia"
	accessmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access/models"

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

	// Install a connector on the pool above
	siaAPI, err := sia.NewIdsecSIAAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	testReachabilityResponse, err := siaAPI.Access().TestConnectorReachability(
		&accessmodels.IdsecSIATestConnectorReachability{
			ConnectorID:           "CMSConnector",
			TargetHostname:        "google.com",
			TargetPort:            443,
			CheckBackendEndpoints: true,
		},
	)
	if err != nil {
		panic(err)
	}
	fmt.Printf("Reachability response: %v\n", testReachabilityResponse)
}
