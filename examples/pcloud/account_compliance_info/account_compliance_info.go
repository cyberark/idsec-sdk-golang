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

	// Retrieve compliance info for a single account.
	info, err := pcloudAPI.Accounts().GetComplianceInfo(&accountsmodels.IdsecPCloudGetAccountComplianceInfo{
		AccountID: "11_1",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Account state: %s\n", info.AccountState)
	fmt.Printf("Platform:      %s\n", info.PlatformID)
	if info.Change != nil {
		fmt.Printf("Change compliant: %s  next schedule: %s\n", info.Change.Compliant, info.Change.NextSchedule)
	}
	if info.Verify != nil {
		fmt.Printf("Verify compliant: %s  next schedule: %s\n", info.Verify.Compliant, info.Verify.NextSchedule)
	}

	// Retrieve compliance info for several accounts in parallel.
	// Per-account errors are captured in each result's Error field rather than
	// failing the entire operation.
	bulkResults, err := pcloudAPI.Accounts().BulkGetComplianceInfo(&accountsmodels.IdsecPCloudBulkGetAccountComplianceInfo{
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
		fmt.Printf("Account %s: state=%s platform=%s\n", r.AccountID, r.ComplianceInfo.AccountState, r.ComplianceInfo.PlatformID)
	}
}
