package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets"
	assetsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/access/assets/models"
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

	// Create an Access Assets service from the authenticator above
	assetsService, err := assets.NewIdsecAccessAssetsService(ispAuth)
	if err != nil {
		panic(err)
	}

	// Retrieve the secret for a specific asset
	secretResponse, err := assetsService.Secret(&assetsmodels.IdsecAccessAssetsSecretRequest{
		AssetID: "your-asset-id-here",
		Reason:  "Troubleshooting connectivity issue",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Secret for asset %s retrieved successfully\n", secretResponse.AssetID)
}
