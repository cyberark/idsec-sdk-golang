//go:build (e2e && sechub) || e2e

package sechub

import (
	"crypto/rand"
	"fmt"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	secretstoresmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sechub/secretstores/models"
	"github.com/cyberark/idsec-sdk-golang/tests/e2e/framework"
)

func creteSecretStoreResourceForTest(t *testing.T, ctx *framework.TestContext,
	name string, desc string, sstype string,
	data secretstoresmodels.IdsecSecHubCreateSecretStoreData) *secretstoresmodels.IdsecSecHubSecretStore {
	// Get the SecHub SecretStores service
	secretStoresSvc, err := ctx.API.SechubSecretstores()
	require.NoError(t, err)

	// Create a secret store with unique name
	secretStoreName := framework.RandomResourceName(name)
	t.Logf("Step 1: Creating secret store: %s", secretStoreName)

	secretStore, err := secretStoresSvc.Create(&secretstoresmodels.IdsecSecHubCreateSecretStore{
		Type:        sstype,
		Name:        secretStoreName,
		Description: desc,
		Data:        data,
	})

	require.NoError(t, err, "Failed to create secretStore with name %s of type %s", secretStoreName, sstype)
	require.NotNil(t, secretStore)
	require.NotNil(t, secretStore.ID)

	assert.Equal(t, secretStoreName, secretStore.Name)
	// Track the created secret store for cleanup
	ctx.TrackResourceByType("SecretStore", secretStore.Name, func() error {
		t.Logf("Cleaning up secretStore used for sync policy: %s", secretStore.Name)
		return secretStoresSvc.Delete(&secretstoresmodels.IdsecSecHubDeleteSecretStore{
			ID: secretStore.ID,
		})
	})
	return secretStore
}

// generateRandom12DigitNumber generates a cryptographically secure random 12-digit number string.
//
// Uses crypto/rand to avoid collisions when tests run concurrently.
// The result is zero-padded to always be exactly 12 characters long.
//
// Returns a 12-character numeric string, e.g. "004931820576".
func randomAWSAccountID() string {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(12), nil) // 10^12
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	return fmt.Sprintf("%012d", n)
}

// randomGCPProjectNumber generates a cryptographically secure random GCP project number string.
//
// GCP project numbers are string representations of 64-bit signed integers with
// a maximum of 18 characters and no leading zeros. This function generates a
// number in the range [1_000_000_000, 999_999_999_999_999_999] (10 to 18 digits),
// guaranteeing no leading zero.
//
// Uses crypto/rand to avoid collisions when tests run concurrently.
//
// Returns a numeric string without leading zeros, e.g. "4931820576214".
func randomGCPProjectNumber() string {
	maxVal := new(big.Int).SetUint64(999_999_999_999_999_999) // largest 18-digit number
	minVal := new(big.Int).SetUint64(1_000_000_000)           // smallest 10-digit number

	// range = max - min + 1
	rangeVal := new(big.Int).Sub(maxVal, minVal)
	rangeVal.Add(rangeVal, big.NewInt(1))

	n, err := rand.Int(rand.Reader, rangeVal)
	if err != nil {
		panic(fmt.Sprintf("crypto/rand failed: %v", err))
	}
	n.Add(n, minVal)
	return n.String()
}

// randomHashiVaultURL generates a random HashiCorp Vault URL for use in e2e tests.
//
// The generated URL follows the format
// "https://<vault-name>.hashicorpcloud.com/" where <vault-name> is a random
// alphanumeric string prefixed with "testvault-".
//
// Uses crypto/rand to avoid collisions when tests run concurrently.
//
// Returns a fully qualified HashiCorp Vault URL string,
// e.g. "https://testvault-a1b2c3d4.hashicorpcloud.com/".
func randomHashiVaultURL() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	prefix := "testvault-"
	suffixLen := 8
	suffix := make([]byte, suffixLen)
	for i := range suffix {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		suffix[i] = charset[idx.Int64()]
	}
	return fmt.Sprintf("https://%s%s.hashicorpcloud.com/", prefix, string(suffix))
}

// randomAzureKeyVaultURL generates a random Azure Key Vault URL for use in e2e tests.
//
// Azure Key Vault names must be 3–24 characters long, contain only alphanumeric
// characters and hyphens, must start and end with a letter or digit, and cannot
// contain consecutive hyphens. The generated URL follows the format
// "https://<vault-name>.vault.azure.net/".
//
// Returns a fully qualified Azure Key Vault URL string,
// e.g. "https://testvault-a1b2c3d4.vault.azure.net/".
func randomAzureKeyVaultURL() string {
	const charset = "abcdefghijklmnopqrstuvwxyz0123456789"
	prefix := "testvault-"
	suffixLen := 8
	suffix := make([]byte, suffixLen)
	for i := range suffix {
		idx, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			panic(fmt.Sprintf("crypto/rand failed: %v", err))
		}
		suffix[i] = charset[idx.Int64()]
	}
	return fmt.Sprintf("https://%s%s.vault.azure.net/", prefix, string(suffix))
}
