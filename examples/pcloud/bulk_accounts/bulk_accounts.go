package main

import (
	"fmt"
	"sync"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	config "github.com/cyberark/idsec-sdk-golang/pkg/config"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
	accountsmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/accounts/models"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
)

const (
	totalAccounts  = 200
	maxConcurrency = 64
	charset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type accountJob struct {
	index int
}

type accountResult struct {
	index     int
	success   bool
	err       error
	accountID string
}

func main() {
	// Perform authentication using IdsecISPAuth to the platform
	// First, create an ISP authentication class
	// Afterwards, perform the authentication
	config.EnableVerboseLogging("DEBUG")
	ispAuth := auth.NewIdsecISPAuth(false)
	_, err := ispAuth.Authenticate(
		nil,
		&authmodels.IdsecAuthProfile{
			Username:           "demo@cyberark.cloud.42070",
			AuthMethod:         authmodels.Identity,
			AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{},
		},
		&authmodels.IdsecSecret{
			Secret: "Cyber123",
		},
		false,
		false,
	)
	if err != nil {
		panic(err)
	}

	// Add a new safe
	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}
	safeName := fmt.Sprintf("bulksafe_%s", common.RandomString(6))
	safe, err := pcloudAPI.Safes().Create(&safesmodels.IdsecPCloudAddSafe{
		SafeName: safeName,
	})
	if err != nil {
		panic(err)
	}
	// Create bulk accounts in batches of 32 go routines with random passwords and usernames
	jobs := make(chan accountJob, totalAccounts)
	results := make(chan accountResult, totalAccounts)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				username := fmt.Sprintf("user_%s", common.RandomString(8))
				password := common.RandomString(16)
				address := fmt.Sprintf("addr_%s.com", common.RandomString(5))

				account, err := pcloudAPI.Accounts().Create(&accountsmodels.IdsecPCloudAddAccount{
					SafeName:   safe.SafeName,
					Secret:     password,
					Username:   username,
					Address:    address,
					SecretType: "password",
					PlatformID: "UnixSSH",
				})

				if err != nil {
					results <- accountResult{index: job.index, success: false, err: err}
				} else {
					results <- accountResult{index: job.index, success: true, err: nil, accountID: account.AccountID}
					fmt.Printf("Created account %d: %s (ID: %s)\n", job.index+1, username, account.AccountID)
				}
			}
		}(i)
	}

	// Send jobs
	go func() {
		for i := 0; i < totalAccounts; i++ {
			jobs <- accountJob{index: i}
		}
		close(jobs)
	}()

	// Wait for all workers to finish
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect results
	successCount := 0
	errorCount := 0
	var createdAccountIDs []string
	for result := range results {
		if result.success {
			successCount++
			createdAccountIDs = append(createdAccountIDs, result.accountID)
		} else {
			errorCount++
			fmt.Printf("Failed to create account %d: %v\n", result.index+1, result.err)
		}
	}

	fmt.Printf("\nBulk account creation completed:\n")
	fmt.Printf("  Total: %d\n", totalAccounts)
	fmt.Printf("  Success: %d\n", successCount)
	fmt.Printf("  Failed: %d\n", errorCount)

	// Delete all the accounts created and safe
	fmt.Printf("\nStarting bulk account deletion...\n")

	deleteJobs := make(chan string, len(createdAccountIDs))
	deleteResults := make(chan accountResult, len(createdAccountIDs))
	var deleteWg sync.WaitGroup

	// Start worker goroutines for deletion
	for i := 0; i < maxConcurrency; i++ {
		deleteWg.Add(1)
		go func(workerID int) {
			defer deleteWg.Done()
			for accountID := range deleteJobs {
				err := pcloudAPI.Accounts().Delete(&accountsmodels.IdsecPCloudDeleteAccount{
					AccountID: accountID,
				})
				if err != nil {
					deleteResults <- accountResult{success: false, err: err, accountID: accountID}
				} else {
					deleteResults <- accountResult{success: true, accountID: accountID}
					fmt.Printf("Deleted account ID: %s\n", accountID)
				}
			}
		}(i)
	}

	// Send deletion jobs
	go func() {
		for _, accountID := range createdAccountIDs {
			deleteJobs <- accountID
		}
		close(deleteJobs)
	}()

	// Wait for all deletion workers to finish
	go func() {
		deleteWg.Wait()
		close(deleteResults)
	}()

	// Collect deletion results
	deleteSuccessCount := 0
	deleteErrorCount := 0
	for result := range deleteResults {
		if result.success {
			deleteSuccessCount++
		} else {
			deleteErrorCount++
			fmt.Printf("Failed to delete account %s: %v\n", result.accountID, result.err)
		}
	}

	fmt.Printf("\nBulk account deletion completed:\n")
	fmt.Printf("  Total: %d\n", len(createdAccountIDs))
	fmt.Printf("  Success: %d\n", deleteSuccessCount)
	fmt.Printf("  Failed: %d\n", deleteErrorCount)

	// Delete the safe
	fmt.Printf("\nDeleting safe '%s'...\n", safe.SafeName)
	err = pcloudAPI.Safes().Delete(&safesmodels.IdsecPCloudDeleteSafe{
		SafeID: safe.SafeID,
	})
	if err != nil {
		fmt.Printf("Failed to delete safe: %v\n", err)
	} else {
		fmt.Printf("Successfully deleted safe '%s'\n", safe.SafeName)
	}
}
