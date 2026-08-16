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

	// List all assets (no filters)
	assetsList, err := assetsService.List()
	if err != nil {
		panic(err)
	}
	for _, asset := range assetsList {
		fmt.Printf("Asset: %s (%s) - %s\n", asset.Name, asset.AssetID, asset.Address)
	}

	// List assets with filters
	filteredAssets, err := assetsService.ListBy(&assetsmodels.IdsecAccessAssetsListAssetsRequest{
		AccessMethod: "vaulted",
		Search:       "address contains 10.0",
	})
	if err != nil {
		panic(err)
	}
	for _, asset := range filteredAssets {
		fmt.Printf("Filtered Asset: %s (%s) - %s\n", asset.Name, asset.AssetID, asset.Address)
	}
}
