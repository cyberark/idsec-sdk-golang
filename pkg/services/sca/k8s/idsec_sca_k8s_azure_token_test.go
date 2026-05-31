package k8s

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func testUnsignedJWT(claims map[string]string) string {
	header := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","typ":"JWT"}`))
	payload, err := json.Marshal(claims)
	if err != nil {
		panic(err)
	}
	body := base64.RawURLEncoding.EncodeToString(payload)
	return header + "." + body + "."
}

func TestAzureIdentitiesMatch_UPNOnly(t *testing.T) {
	elevate := azureJWTIdentity{UPN: "eva.ravish.int2@cybrsca.onmicrosoft.com", Email: "onlineshopping374@gmail.com"}
	azure := azureJWTIdentity{UPN: "eva.ravish.int2@cybrsca.onmicrosoft.com"}
	require.True(t, azureIdentitiesMatch(elevate, azure))
}

func TestAzureIdentitiesMatch_EmailWhenBothPresent(t *testing.T) {
	elevate := azureJWTIdentity{UPN: "user@tenant.com", Email: "same@example.com"}
	azure := azureJWTIdentity{UPN: "other@tenant.com", Email: "same@example.com"}
	require.True(t, azureIdentitiesMatch(elevate, azure))
}

func TestAzureIdentitiesMatch_EmailMismatchFallsBackToUPN(t *testing.T) {
	elevate := azureJWTIdentity{
		UPN:   "eva.ravish.int2@cybrsca.onmicrosoft.com",
		Email: "onlineshopping374@gmail.com",
	}
	azure := azureJWTIdentity{
		UPN:   "eva.ravish.int2@cybrsca.onmicrosoft.com",
		Email: "different@gmail.com",
	}
	// Both have email but they differ — fall through to UPN match.
	require.True(t, azureIdentitiesMatch(elevate, azure))
}

func TestAzureIdentitiesMatch_NoMatch(t *testing.T) {
	elevate := azureJWTIdentity{UPN: "alice@tenant.com", Email: "alice@gmail.com"}
	azure := azureJWTIdentity{UPN: "bob@tenant.com", Email: "bob@gmail.com"}
	require.False(t, azureIdentitiesMatch(elevate, azure))
}

func TestValidateAzureCLIIdentity_RealWorldClaimMix(t *testing.T) {
	elevate := testUnsignedJWT(map[string]string{
		"preferred_username": "eva.ravish.int2@cybrsca.onmicrosoft.com",
		"email":              "onlineshopping374@gmail.com",
	})
	azure := testUnsignedJWT(map[string]string{
		"upn":   "eva.ravish.int2@cybrsca.onmicrosoft.com",
		"email": "eva.ravish.int2@cybrsca.onmicrosoft.com",
	})
	require.NoError(t, validateAzureCLIIdentity(elevate, azure))
}

func TestValidateAzureCLIIdentity_Mismatch(t *testing.T) {
	elevate := testUnsignedJWT(map[string]string{
		"preferred_username": "eva.ravish.int2@cybrsca.onmicrosoft.com",
	})
	azure := testUnsignedJWT(map[string]string{
		"upn": "bob@tenant.com",
	})
	err := validateAzureCLIIdentity(elevate, azure)
	require.Error(t, err)
	require.Contains(t, err.Error(), "does not match")
	require.NotContains(t, err.Error(), "bob@tenant.com")
	require.NotContains(t, err.Error(), "eva.ravish.int2@cybrsca.onmicrosoft.com")
}

func TestExtractAzureJWTIdentity(t *testing.T) {
	token := testUnsignedJWT(map[string]string{
		"upn":   "user@contoso.com",
		"email": "user@contoso.com",
	})
	id, err := extractAzureJWTIdentity(token, []string{"upn", "preferred_username"})
	require.NoError(t, err)
	require.Equal(t, "user@contoso.com", id.UPN)
	require.Equal(t, "user@contoso.com", id.Email)
}
