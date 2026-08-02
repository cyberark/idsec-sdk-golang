package k8s

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
	k8smodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/k8s/models"
)

const testCLISignatureIDToken = "test-id-token-for-cli-signature"

func TestCLISignatureTimeWindow_UTC(t *testing.T) {
	// 2024-01-15 12:00:07 UTC → unix 1705320007 → floor(/5) = 341064001
	now := time.Date(2024, 1, 15, 12, 0, 7, 0, time.UTC)
	require.Equal(t, int64(341064001), cliSignatureTimeWindow(now))

	// Same instant in a non-UTC zone must yield the same window.
	ist := time.FixedZone("IST", 5*3600+30*60)
	nowIST := time.Date(2024, 1, 15, 17, 30, 7, 0, ist)
	require.Equal(t, cliSignatureTimeWindow(now), cliSignatureTimeWindow(nowIST))
}

func TestNormalizeCLISignaturePath(t *testing.T) {
	require.Equal(t, "/access/elevate/clusters", normalizeCLISignaturePath("access/elevate/clusters"))
	require.Equal(t, "/access/elevate/clusters", normalizeCLISignaturePath("/access/elevate/clusters"))
	require.Equal(t, "/", normalizeCLISignaturePath(""))
	require.Equal(t, "/", normalizeCLISignaturePath("   "))
}

func TestComputeCLISignature_Deterministic(t *testing.T) {
	now := time.Date(2024, 1, 15, 12, 0, 7, 0, time.UTC)
	path := "/access/AWS/eligibility/clusters/evaluate"

	sig1 := computeCLISignature(testCLISignatureIDToken, path, now)
	sig2 := computeCLISignature(testCLISignatureIDToken, "access/AWS/eligibility/clusters/evaluate", now)
	require.Equal(t, sig1, sig2, "path with/without leading slash must match")

	_, err := base64.StdEncoding.DecodeString(sig1)
	require.NoError(t, err, "signature must be standard Base64")

	require.NotEqual(t, sig1, computeCLISignature("other-token", path, now))

	prev := now.Add(-5 * time.Second)
	require.NotEqual(t, sig1, computeCLISignature(testCLISignatureIDToken, path, prev))
}

func TestComputeCLISignature_MessageFormat(t *testing.T) {
	now := time.Date(2024, 1, 15, 12, 0, 7, 0, time.UTC)
	path := "/access/elevate/clusters"
	got := computeCLISignature(testCLISignatureIDToken, path, now)

	mac := hmac.New(sha256.New, []byte(testCLISignatureIDToken))
	_, _ = mac.Write([]byte("341064001|/access/elevate/clusters"))
	want := base64.StdEncoding.EncodeToString(mac.Sum(nil))
	require.Equal(t, want, got)
}

func TestEvaluateEligibility_SetsCLISignatureHeader(t *testing.T) {
	var capturedSig string
	var headerPresentAfter bool
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockEvaluateResponse,
			OnRequest: func(r *http.Request) {
				capturedSig = r.Header.Get(cliSignatureHeader)
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.EvaluateEligibility(&k8smodels.IdsecSCAK8sEvaluateRequest{
		Targets: []k8smodels.IdsecSCAK8sEvaluateTarget{validEvaluateFQDNTarget},
	}, "AWS")
	require.NoError(t, err)

	require.NotEmpty(t, capturedSig)
	want := computeCLISignature(
		testCLISignatureIDToken,
		"/access/AWS/eligibility/clusters/evaluate",
		time.Now().UTC(),
	)
	// Allow tw-1 in case the 5s boundary is crossed between compute and assert.
	wantPrev := computeCLISignature(
		testCLISignatureIDToken,
		"/access/AWS/eligibility/clusters/evaluate",
		time.Now().UTC().Add(-5*time.Second),
	)
	require.True(t, capturedSig == want || capturedSig == wantPrev,
		"got %q, want %q or %q", capturedSig, want, wantPrev)

	headerPresentAfter = client.GetHeaders()[cliSignatureHeader] != ""
	require.False(t, headerPresentAfter, "X-CLI-Signature must be removed after the call")
}

func TestElevate_SetsCLISignatureHeader(t *testing.T) {
	var capturedSig string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: mockElevateResponse,
			OnRequest: func(r *http.Request) {
				capturedSig = r.Header.Get(cliSignatureHeader)
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	_, err := svc.Elevate(&validFQDNReq)
	require.NoError(t, err)

	require.NotEmpty(t, capturedSig)
	want := computeCLISignature(testCLISignatureIDToken, "/access/elevate/clusters", time.Now().UTC())
	wantPrev := computeCLISignature(
		testCLISignatureIDToken,
		"/access/elevate/clusters",
		time.Now().UTC().Add(-5*time.Second),
	)
	require.True(t, capturedSig == want || capturedSig == wantPrev,
		"got %q, want %q or %q", capturedSig, want, wantPrev)
	require.Empty(t, client.GetHeaders()[cliSignatureHeader])
}

func TestGenerateKubeconfig_SetsCLISignatureHeader(t *testing.T) {
	var capturedSig string
	var capturedPath string
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{"aws":"apiVersion: v1\nkind: Config\n"}`,
			OnRequest: func(r *http.Request) {
				capturedSig = r.Header.Get(cliSignatureHeader)
				capturedPath = r.URL.Path
			},
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	_, err := svc.GenerateKubeconfig(&k8smodels.IdsecSCAK8sGenerateKubeconfigRequest{
		CSP: "AWS",
		All: "false",
	})
	require.NoError(t, err)
	require.Equal(t, "/k8s/kube-config/AWS", capturedPath)
	require.NotEmpty(t, capturedSig)

	want := computeCLISignature(testCLISignatureIDToken, "k8s/kube-config/AWS", time.Now().UTC())
	wantPrev := computeCLISignature(
		testCLISignatureIDToken,
		"k8s/kube-config/AWS",
		time.Now().UTC().Add(-5*time.Second),
	)
	require.True(t, capturedSig == want || capturedSig == wantPrev,
		"got %q, want %q or %q", capturedSig, want, wantPrev)
	require.Empty(t, client.GetHeaders()[cliSignatureHeader])
}

func TestPostWithCLISignature_MissingToken(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(_ *http.Request) bool { return true },
			StatusCode:   http.StatusOK,
			ResponseBody: `{}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	client.UpdateToken("", "Bearer")

	_, err := svc.postWithCLISignature("access/elevate/clusters", map[string]string{})
	require.Error(t, err)
	require.Contains(t, err.Error(), "ISP auth token is not available")
}
