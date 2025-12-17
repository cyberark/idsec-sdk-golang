package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/cce"
	awsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/cce/aws/models"
)

func main() {
	// This example demonstrates how to trigger an AWS organization discovery scan in CCE.
	// The scan discovers new accounts that have been added to AWS organizations.

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

	// Create CCE API instance
	cceAPI, err := cce.NewIdsecCCEAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	// Trigger an AWS organization discovery scan
	// Note: You can only trigger a scan if no other scan for this organization is currently in progress.
	// You can optionally specify an organization ID to scan a specific organization.
	_, err = cceAPI.AWS().ScanOrganization(&awsmodels.IdsecCCEAWSScanOrganization{
		// OrganizationID: nil, // Optional: specify organization ID to scan specific organization
	})
	if err != nil {
		panic(err)
	}

	fmt.Println("AWS organization discovery scan triggered successfully!")
	fmt.Println("The scan will discover new accounts added to organizations.")
}
