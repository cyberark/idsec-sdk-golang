package main

import (
	"fmt"
	"os"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
)

func main() {
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

	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	// Retrieve the overview for a single account.
	overview, err := pcloudAPI.Accounts().GetOverview(&accountsmodels.IdsecPCloudGetAccountOverview{
		AccountID: "11_1",
	})
	if err != nil {
		panic(err)
	}
	if overview.Compliance != nil {
		fmt.Printf("Compliant:       %v\n", overview.Compliance.IsCompliant)
		fmt.Printf("Last modified by: %s\n", overview.Compliance.LastModifiedBy)
	}
	if overview.Details != nil {
		fmt.Printf("Safe:            %s\n", overview.Details.SafeName)
		fmt.Printf("Managed by CPM:  %v\n", overview.Details.ManagedByCPM)
		fmt.Printf("CPM status:      %s\n", overview.Details.CPMStatus)
	}
	fmt.Printf("Available tabs: %v\n", overview.AvailableTabs)

	// Retrieve the overview for several accounts in parallel.
	// Per-account errors are captured in each result's Error field rather than
	// failing the entire operation.
	bulkResults, err := pcloudAPI.Accounts().BulkGetOverview(&accountsmodels.IdsecPCloudBulkGetAccountOverview{
		AccountIDs:     []string{"11_1", "11_2", "11_3"},
		MaxConcurrency: 4,
	})
	if err != nil {
		panic(err)
	}
	for _, r := range bulkResults {
		if r.Error != "" {
			fmt.Printf("Account %s: error - %s\n", r.AccountID, r.Error)
			continue
		}
		compliant := r.Overview.Compliance != nil && r.Overview.Compliance.IsCompliant
		fmt.Printf("Account %s: compliant=%v tabs=%v\n", r.AccountID, compliant, r.Overview.AvailableTabs)
	}
}
