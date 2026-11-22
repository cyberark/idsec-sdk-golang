package k8s

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"os"
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

func TestValidateAzureCLIIdentity_RealWorldClaimMix(t *testing.T) {
	azure := testUnsignedJWT(map[string]string{
		"upn":   "alex.morgan.int2@contoso.onmicrosoft.com",
		"email": "alex.morgan.personal@example.net",
	})
	require.NoError(t, validateAzureCLIIdentity("alex.morgan.int2@contoso.onmicrosoft.com", azure))
}

// No cloudUserName means an older backend or a pre-upgrade cache entry; the
// check must be skipped rather than blocking access.
func TestValidateAzureCLIIdentity_SkippedWithoutCloudUserName(t *testing.T) {
	azure := testUnsignedJWT(map[string]string{"upn": "bob@tenant.com"})
	require.NoError(t, validateAzureCLIIdentity("", azure))
}

// The error names both accounts so a user who believes they are already signed
// in as the elevated user can see which account az actually resolved to.
func TestValidateAzureCLIIdentity_MismatchNamesBothAccounts(t *testing.T) {
	azure := testUnsignedJWT(map[string]string{"upn": "bob@tenant.com"})
	err := validateAzureCLIIdentity("alex.morgan.int2@contoso.onmicrosoft.com", azure)
	require.Error(t, err)
	require.Equal(t,
		"Signed in as bob@tenant.com, but authentication requires the elevated user (alex.morgan.int2@contoso.onmicrosoft.com). "+
			"To fix: run 'az logout', then az login again, using the elevated user (alex.morgan.int2@contoso.onmicrosoft.com).",
		err.Error())
}

func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	orig := os.Stderr
	r, w, err := os.Pipe()
	require.NoError(t, err)
	os.Stderr = w
	defer func() { os.Stderr = orig }()
	fn()
	require.NoError(t, w.Close())
	out, err := io.ReadAll(r)
	require.NoError(t, err)
	return string(out)
}

func TestAnnounceExpectedAzureCloudUser(t *testing.T) {
	out := captureStderr(t, func() { announceExpectedAzureCloudUser("eva@contoso.com") })
	require.Contains(t, out, "| INFO |")
	require.Contains(t, out, "Azure authentication az login requires the elevated user (eva@contoso.com).")
}

// Falls back to the email claim when the token carries no UPN.
func TestValidateAzureCLIIdentity_MismatchNamesEmailWhenNoUPN(t *testing.T) {
	azure := testUnsignedJWT(map[string]string{"email": "bob@tenant.com"})
	err := validateAzureCLIIdentity("alex.morgan.int2@contoso.onmicrosoft.com", azure)
	require.Error(t, err)
	require.Contains(t, err.Error(), "bob@tenant.com")
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
