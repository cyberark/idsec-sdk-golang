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

	// List all activities for a single account.
	// SafeName is resolved automatically when omitted.
	activities, err := pcloudAPI.Accounts().ListActivities(&accountsmodels.IdsecPCloudListAccountActivities{
		AccountID: "11_1",
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Total activities: %d\n", len(activities))
	for _, a := range activities {
		fmt.Printf("  [%d] user=%s action=%s alert=%v\n", a.Date, a.User, a.Action, a.Alert)
	}

	// List activities filtered by user and restricted to a date range.
	filtered, err := pcloudAPI.Accounts().ListActivitiesBy(&accountsmodels.IdsecPCloudAccountActivitiesFilter{
		AccountID:      "11_1",
		User:           "Administrator",
		ActionContains: "Retrieve",
		FromDate:       1700000000,
		ToDate:         1800000000,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Filtered activities (Administrator / Retrieve): %d\n", len(filtered))

	// List only alert-triggering activities.
	alerts, err := pcloudAPI.Accounts().ListActivitiesBy(&accountsmodels.IdsecPCloudAccountActivitiesFilter{
		AccountID:  "11_1",
		AlertsOnly: true,
	})
	if err != nil {
		panic(err)
	}
	fmt.Printf("Alert activities: %d\n", len(alerts))

	// Retrieve activities for several accounts in parallel.
	// Per-account errors are captured in each result's Error field rather than
	// failing the entire operation.
	bulkResults, err := pcloudAPI.Accounts().BulkListActivities(&accountsmodels.IdsecPCloudBulkListAccountActivities{
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
		fmt.Printf("Account %s: %d activities\n", r.AccountID, len(r.Activities))
	}
}
