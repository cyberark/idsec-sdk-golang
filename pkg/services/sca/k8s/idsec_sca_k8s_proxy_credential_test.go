package k8s

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

func TestParseDpaSsoExpiresAt(t *testing.T) {
	t.Parallel()
	expiresAt, err := parseDpaSsoExpiresAt(&k8smodels.IdsecSCAK8sDpaSsoAcquireMetadata{
		ExpiresAt: "2026-05-31T13:34:16.939329",
	})
	require.NoError(t, err)
	require.Equal(t, 2026, expiresAt.Year())
	require.Equal(t, time.May, expiresAt.Month())
	require.Equal(t, 31, expiresAt.Day())
	require.Equal(t, 13, expiresAt.Hour())
	require.Equal(t, 34, expiresAt.Minute())
}

func TestParseDpaSsoExpiresAt_Empty(t *testing.T) {
	t.Parallel()
	_, err := parseDpaSsoExpiresAt(&k8smodels.IdsecSCAK8sDpaSsoAcquireMetadata{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "expires_at")
}

func TestBuildProxyExecCredential_ExpirationTimestamp(t *testing.T) {
	t.Parallel()
	// BuildProxyExecCredential now writes the given timestamp verbatim; the
	// early-refresh buffer is applied by the caller, not here.
	expirationTimestamp := time.Date(2026, 5, 31, 13, 34, 16, 0, time.UTC)
	cred := BuildProxyExecCredential("CERT", "KEY", expirationTimestamp)
	require.Equal(t, "2026-05-31T13:34:16Z", cred.Status.ExpirationTimestamp)
}

func TestProxyExecCredentialExpiresAt_RoundTrip(t *testing.T) {
	t.Parallel()
	expirationTimestamp := time.Date(2026, 5, 31, 13, 34, 16, 0, time.UTC)
	cred := BuildProxyExecCredential("CERT", "KEY", expirationTimestamp)
	got, err := ProxyExecCredentialExpiresAt(cred)
	require.NoError(t, err)
	require.True(t, got.Equal(expirationTimestamp))
}
