package main

import (
	"fmt"
	"sync"

	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	config "github.com/cyberark/idsec-sdk-golang/pkg/config"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud"
	safesmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/pcloud/safes/models"
)

const (
	totalSafes     = 200
	maxConcurrency = 64
	charset        = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
)

type safeJob struct {
	index int
}

type safeResult struct {
	index    int
	success  bool
	err      error
	safeID   string
	safeName string
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

	// Create PCloud API client
	pcloudAPI, err := pcloud.NewIdsecPCloudAPI(ispAuth.(*auth.IdsecISPAuth))
	if err != nil {
		panic(err)
	}

	// Create bulk safes in batches of concurrent go routines with random names
	jobs := make(chan safeJob, totalSafes)
	results := make(chan safeResult, totalSafes)
	var wg sync.WaitGroup

	// Start worker goroutines
	for i := 0; i < maxConcurrency; i++ {
		wg.Add(1)
		go func(workerID int) {
			defer wg.Done()
			for job := range jobs {
				safeName := fmt.Sprintf("bulksafe_%s", common.RandomString(16))

				safe, err := pcloudAPI.Safes().Create(&safesmodels.IdsecPCloudAddSafe{
					SafeName: safeName,
				})

				if err != nil {
					results <- safeResult{index: job.index, success: false, err: err}
				} else {
					results <- safeResult{index: job.index, success: true, err: nil, safeID: safe.SafeID, safeName: safe.SafeName}
					fmt.Printf("Created safe %d: %s (ID: %s)\n", job.index+1, safe.SafeName, safe.SafeID)
				}
			}
		}(i)
	}

	// Send jobs
	go func() {
		for i := 0; i < totalSafes; i++ {
			jobs <- safeJob{index: i}
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
	var createdSafeIDs []string
	for result := range results {
		if result.success {
			successCount++
			createdSafeIDs = append(createdSafeIDs, result.safeID)
		} else {
			errorCount++
			fmt.Printf("Failed to create safe %d: %v\n", result.index+1, result.err)
		}
	}

	fmt.Printf("\nBulk safe creation completed:\n")
	fmt.Printf("  Total: %d\n", totalSafes)
	fmt.Printf("  Success: %d\n", successCount)
	fmt.Printf("  Failed: %d\n", errorCount)

	// Delete all the safes created
	fmt.Printf("\nStarting bulk safe deletion...\n")

	deleteJobs := make(chan string, len(createdSafeIDs))
	deleteResults := make(chan safeResult, len(createdSafeIDs))
	var deleteWg sync.WaitGroup

	// Start worker goroutines for deletion
	for i := 0; i < maxConcurrency; i++ {
		deleteWg.Add(1)
		go func(workerID int) {
			defer deleteWg.Done()
			for safeID := range deleteJobs {
				err := pcloudAPI.Safes().Delete(&safesmodels.IdsecPCloudDeleteSafe{
					SafeID: safeID,
				})
				if err != nil {
					deleteResults <- safeResult{success: false, err: err, safeID: safeID}
				} else {
					deleteResults <- safeResult{success: true, safeID: safeID}
					fmt.Printf("Deleted safe ID: %s\n", safeID)
				}
			}
		}(i)
	}

	// Send deletion jobs
	go func() {
		for _, safeID := range createdSafeIDs {
			deleteJobs <- safeID
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
			fmt.Printf("Failed to delete safe %s: %v\n", result.safeID, result.err)
		}
	}

	fmt.Printf("\nBulk safe deletion completed:\n")
	fmt.Printf("  Total: %d\n", len(createdSafeIDs))
	fmt.Printf("  Success: %d\n", deleteSuccessCount)
	fmt.Printf("  Failed: %d\n", deleteErrorCount)
}
