package k8s

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	"github.com/stretchr/testify/require"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	scainternal "github.com/cyberark/idsec-sdk-golang/pkg/services/sca/internal"
)

const mockDpaSsoAcquireResponse = `{
  "token": {
    "client_certificate": "-----BEGIN CERTIFICATE-----\nCERT\n-----END CERTIFICATE-----\n",
    "private_key": "-----BEGIN PRIVATE KEY-----\nKEY\n-----END PRIVATE KEY-----\n"
  },
  "metadata": {
    "expires_at": "2030-06-01T12:00:00.000000"
  }
}`

// preFilledFuture builds a ProxyKeyFuture that is already complete so Wait()
// and CheckNow() return immediately without a real network call.
// elapsed is fixed at 1ms so JWKSElapsed() is always positive after Wait().
func preFilledFuture(key *rsa.PublicKey, kid string, fetchErr error) *ProxyKeyFuture {
	f := &ProxyKeyFuture{
		startedAt: time.Now(),
		done:      make(chan struct{}),
		key:       key,
		kid:       kid,
		err:       fetchErr,
		elapsed:   time.Millisecond,
	}
	close(f.done)
	return f
}

func TestGenerateProxyExecCredential_UninitializedService(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "not initialized")
}

func TestGenerateProxyExecCredential_UnsupportedCSP(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	cred, err := svc.GenerateProxyExecCredential("ibm", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "unsupported CSP for kubectl-login proxy flow")
}

func TestGenerateProxyExecCredential_AzureMissingK8sToken(t *testing.T) {
	svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
	cred, err := svc.GenerateProxyExecCredential("AZURE", &IdsecSCAK8sClusterContext{CSP: "AZURE"})
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "K8sToken")
}

func TestGenerateProxyExecCredential_Success(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return r.Method == http.MethodPost },
			StatusCode:   http.StatusCreated,
			ResponseBody: mockDpaSsoAcquireResponse,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.GenerateProxyExecCredential("AWS", &IdsecSCAK8sClusterContext{CSP: "AWS"})
	require.NoError(t, err)
	require.NotNil(t, cred)
	require.Equal(t, "client.authentication.k8s.io/v1beta1", cred.APIVersion)
	require.Equal(t, "ExecCredential", cred.Kind)
	require.Contains(t, cred.Status.ClientCertificateData, "CERT")
	require.Contains(t, cred.Status.ClientKeyData, "KEY")
	require.NotEmpty(t, cred.Status.ExpirationTimestamp)
}

func TestGenerateProxyExecCredential_MissingExpiresAt(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusCreated,
			ResponseBody: `{"token":{"client_certificate":"CERT","private_key":"KEY"},"metadata":{}}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "expires_at")
}

func TestGenerateProxyExecCredential_MissingCertificateInResponse(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusCreated,
			ResponseBody: `{"token": {}}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.GenerateProxyExecCredential("AWS", nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "proxy client certificate generation failed")
}

func TestGenerateProxyExecCredential_WithJWE(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	var capturedBody map[string]interface{}
	var capturedJWKSKid string
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "jwks"):
			capturedJWKSKid = r.URL.Query().Get("kid")
			jwk := jose.JSONWebKey{Key: &privKey.PublicKey, KeyID: capturedJWKSKid, Use: "enc"}
			resp := dpaSsoJWKSResponse{Keys: []jose.JSONWebKey{jwk}}
			w.WriteHeader(http.StatusOK)
			_ = json.NewEncoder(w).Encode(resp)
		case r.Method == http.MethodPost:
			_ = json.NewDecoder(r.Body).Decode(&capturedBody)
			w.WriteHeader(http.StatusCreated)
			_, _ = w.Write([]byte(mockDpaSsoAcquireResponse))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer testServer.Close()

	client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
	client.BaseURL = testServer.URL
	ispClient := &isp.IdsecISPServiceClient{IdsecClient: client}

	svc := setupK8sElevateService(ispClient)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, ispClient)
	svc.dpaISP = dpaBase

	const rawK8SToken = "k8s-jwt-token"
	cred, err := svc.generateDPAProxyExecCredential(&IdsecSCAK8sClusterContext{
		K8sToken: rawK8SToken,
		RootCA:   testProxyJWERootCA,
	}, nil)
	require.NoError(t, err)
	require.NotNil(t, cred)

	require.NotEmpty(t, capturedJWKSKid)
	require.Len(t, capturedJWKSKid, 8, "kid must be yyyymmdd")
	_, parseErr := time.Parse("20060102", capturedJWKSKid)
	require.NoError(t, parseErr, "kid must be a valid date in yyyymmdd format")

	jweValue, ok := capturedBody["jwe_extension_value"].(string)
	require.True(t, ok, "jwe_extension_value must be a string")
	require.NotEqual(t, rawK8SToken, jweValue, "jwe_extension_value must be encrypted, not the raw token")
	require.Len(t, strings.Split(jweValue, "."), 5, "jwe_extension_value must be a JWE compact string (5 segments)")

	payload := decryptProxyJWEPayload(t, jweValue, privKey)
	require.Equal(t, rawK8SToken, payload["k8s_token"],
		"k8s token must be JSON-wrapped under the k8s_token key before encryption")
	require.Equal(t, testProxyJWERootCA, payload["root_ca"],
		"cluster root CA must be JSON-wrapped under the root_ca key before encryption")
}

func TestGenerateProxyExecCredential_MissingRootCAWhenJWESet(t *testing.T) {
	svc := &IdsecSCAK8sService{}
	cred, err := svc.generateDPAProxyExecCredential(&IdsecSCAK8sClusterContext{
		K8sToken: "k8s-jwt-token",
	}, nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "root_ca is required when k8s_token is set")
}

func TestGenerateProxyExecCredential_Non201Status(t *testing.T) {
	client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
		{
			Matcher:      func(r *http.Request) bool { return true },
			StatusCode:   http.StatusBadRequest,
			ResponseBody: `{"error":"bad request"}`,
		},
	})
	defer cleanup()

	svc := setupK8sElevateService(client)
	dpaBase := &services.IdsecISPBaseService{}
	scainternal.InjectISPClient(dpaBase, client)
	svc.dpaISP = dpaBase

	cred, err := svc.generateDPAProxyExecCredential(nil, nil)
	require.Error(t, err)
	require.Nil(t, cred)
	require.Contains(t, err.Error(), "proxy client certificate generation failed")
	require.Contains(t, err.Error(), "400")
}

func TestBeginProxyKeyPrefetch(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := dpaSsoJWKSKeyID()

	tests := []struct {
		name        string
		statusCode  int
		body        func() string
		wantErr     bool
		wantErrText string
	}{
		{
			name:       "success_returns_key_and_kid",
			statusCode: http.StatusOK,
			body:       func() string { return jwksBodyForRSAKey(t, kid, &privKey.PublicKey) },
		},
		{
			name:        "server_error_propagates",
			statusCode:  http.StatusInternalServerError,
			body:        func() string { return `{"error":"internal"}` },
			wantErr:     true,
			wantErrText: "500",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client, cleanup := scainternal.SetupMockSCAService(t, []scainternal.MockEndpointConfig{
				{
					Matcher:      func(r *http.Request) bool { return r.Method == http.MethodGet },
					StatusCode:   tt.statusCode,
					ResponseBody: tt.body(),
				},
			})
			defer cleanup()

			svc := setupK8sElevateService(client)
			dpaBase := &services.IdsecISPBaseService{}
			scainternal.InjectISPClient(dpaBase, client)
			svc.dpaISP = dpaBase

			future := svc.BeginProxyKeyPrefetch(false)
			require.NotNil(t, future)
			require.False(t, future.startedAt.IsZero(), "startedAt must be set")

			key, retKid, err := future.Wait()
			if tt.wantErr {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.wantErrText)
				require.Nil(t, key)
			} else {
				require.NoError(t, err)
				require.NotNil(t, key)
				require.Equal(t, kid, retKid)
				require.Greater(t, future.JWKSElapsed(), time.Duration(0), "elapsed must be positive after Wait")
			}
		})
	}
}

// TestProxyKeyFutureWait_Idempotent verifies that calling Wait() more than once
// never deadlocks and always returns the same cached result, both sequentially
// and when multiple goroutines race to call Wait() at the same time.
func TestProxyKeyFutureWait_Idempotent(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	kid := dpaSsoJWKSKeyID()

	t.Run("sequential", func(t *testing.T) {
		future := preFilledFuture(&privKey.PublicKey, kid, nil)
		for i := range 3 {
			key, retKid, waitErr := future.Wait()
			require.NoError(t, waitErr, "call %d: unexpected error", i+1)
			require.Equal(t, &privKey.PublicKey, key, "call %d: key must be stable", i+1)
			require.Equal(t, kid, retKid, "call %d: kid must be stable", i+1)
			require.Greater(t, future.JWKSElapsed(), time.Duration(0), "call %d: elapsed must be positive", i+1)
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		const goroutines = 20
		future := preFilledFuture(&privKey.PublicKey, kid, nil)

		keys := make([]*rsa.PublicKey, goroutines)
		kids := make([]string, goroutines)
		errs := make([]error, goroutines)

		var ready, done sync.WaitGroup
		ready.Add(goroutines)
		done.Add(goroutines)
		start := make(chan struct{})

		for i := range goroutines {
			go func(idx int) {
				defer done.Done()
				ready.Done()
				<-start // all goroutines unblock simultaneously
				keys[idx], kids[idx], errs[idx] = future.Wait()
			}(i)
		}

		ready.Wait() // wait until all goroutines are parked at <-start
		close(start) // release them all at once
		done.Wait()

		for i := range goroutines {
			require.NoError(t, errs[i], "goroutine %d: unexpected error", i)
			require.Equal(t, &privKey.PublicKey, keys[i], "goroutine %d: key must be stable", i)
			require.Equal(t, kid, kids[i], "goroutine %d: kid must be stable", i)
		}
		require.Greater(t, future.JWKSElapsed(), time.Duration(0), "elapsed must be positive after concurrent Wait")
	})
}

func TestGenerateProxyExecCredentialWithPrefetch(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	t.Run("uninitialized_service", func(t *testing.T) {
		svc := &IdsecSCAK8sService{}
		_, err := svc.GenerateProxyExecCredentialWithPrefetch("AWS", nil, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "not initialized")
	})

	t.Run("unsupported_csp", func(t *testing.T) {
		svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
		_, err := svc.GenerateProxyExecCredentialWithPrefetch("ibm", &IdsecSCAK8sClusterContext{K8sToken: "tok"}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "unsupported CSP")
	})

	t.Run("missing_k8s_token", func(t *testing.T) {
		svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
		_, err := svc.GenerateProxyExecCredentialWithPrefetch("AWS", &IdsecSCAK8sClusterContext{}, nil)
		require.Error(t, err)
		require.Contains(t, err.Error(), "K8sToken required")
	})

	// success_no_extra_jwks_call verifies that GenerateProxyExecCredentialWithPrefetch
	// uses the pre-fetched key and never calls the JWKS endpoint a second time.
	for _, csp := range []string{"AWS", "AZURE"} {
		csp := csp
		t.Run("success_no_extra_jwks_call_"+strings.ToLower(csp), func(t *testing.T) {
			var jwksHits int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				switch {
				case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "jwks"):
					// Any call here means the pre-fetched key was NOT used — test will fail.
					atomic.AddInt32(&jwksHits, 1)
					w.WriteHeader(http.StatusInternalServerError)
				case r.Method == http.MethodPost:
					w.WriteHeader(http.StatusCreated)
					_, _ = w.Write([]byte(mockDpaSsoAcquireResponse))
				default:
					w.WriteHeader(http.StatusNotFound)
				}
			}))
			defer server.Close()

			client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
			client.BaseURL = server.URL
			ispClient := &isp.IdsecISPServiceClient{IdsecClient: client}
			svc := setupK8sElevateService(ispClient)
			dpaBase := &services.IdsecISPBaseService{}
			scainternal.InjectISPClient(dpaBase, ispClient)
			svc.dpaISP = dpaBase

			future := preFilledFuture(&privKey.PublicKey, dpaSsoJWKSKeyID(), nil)
			ctx := &IdsecSCAK8sClusterContext{K8sToken: "test-token", RootCA: testProxyJWERootCA}
			cred, err := svc.GenerateProxyExecCredentialWithPrefetch(csp, ctx, future)
			require.NoError(t, err)
			require.NotNil(t, cred)
			require.Contains(t, cred.Status.ClientCertificateData, "CERT")
			require.Contains(t, cred.Status.ClientKeyData, "KEY")
			require.EqualValues(t, 0, atomic.LoadInt32(&jwksHits), "pre-fetched key must not trigger a JWKS call")
			require.Greater(t, future.JWKSElapsed(), time.Duration(0), "elapsed must be positive after Wait")
		})
	}

	// stale_kid_triggers_refetch covers the day-boundary edge case: a prefetch
	// started before UTC midnight completes with yesterday's kid, and a long
	// Elevate/token-acquisition wait crosses into today. The stale key must be
	// discarded and refetched with today's kid before JWE encryption.
	t.Run("stale_kid_triggers_refetch", func(t *testing.T) {
		freshKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)
		freshKid := dpaSsoJWKSKeyID()

		var jwksHits int32
		var gotKid string
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			switch {
			case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "jwks"):
				atomic.AddInt32(&jwksHits, 1)
				gotKid = r.URL.Query().Get("kid")
				w.WriteHeader(http.StatusOK)
				_, _ = w.Write([]byte(jwksBodyForRSAKey(t, freshKid, &freshKey.PublicKey)))
			case r.Method == http.MethodPost:
				w.WriteHeader(http.StatusCreated)
				_, _ = w.Write([]byte(mockDpaSsoAcquireResponse))
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		}))
		defer server.Close()

		client := common.NewIdsecClient("", "", "", "Authorization", nil, nil, "", false)
		client.BaseURL = server.URL
		ispClient := &isp.IdsecISPServiceClient{IdsecClient: client}
		svc := setupK8sElevateService(ispClient)
		dpaBase := &services.IdsecISPBaseService{}
		scainternal.InjectISPClient(dpaBase, ispClient)
		svc.dpaISP = dpaBase

		staleKid := "20200101" // simulates a prefetch begun on a prior UTC day
		future := preFilledFuture(&privKey.PublicKey, staleKid, nil)
		ctx := &IdsecSCAK8sClusterContext{K8sToken: "test-token", RootCA: testProxyJWERootCA}
		cred, err := svc.GenerateProxyExecCredentialWithPrefetch("AWS", ctx, future)
		require.NoError(t, err)
		require.NotNil(t, cred)
		require.EqualValues(t, 1, atomic.LoadInt32(&jwksHits), "stale kid must trigger exactly one refetch")
		require.Equal(t, freshKid, gotKid, "refetch must request the current day's kid")
	})

	t.Run("prefetch_error_propagates", func(t *testing.T) {
		future := preFilledFuture(nil, "", fmt.Errorf("JWKS fetch failed: 503"))

		svc := setupK8sElevateService(&isp.IdsecISPServiceClient{})
		dpaBase := &services.IdsecISPBaseService{}
		scainternal.InjectISPClient(dpaBase, &isp.IdsecISPServiceClient{})
		svc.dpaISP = dpaBase

		ctx := &IdsecSCAK8sClusterContext{K8sToken: "tok", RootCA: testProxyJWERootCA}
		_, err := svc.GenerateProxyExecCredentialWithPrefetch("AWS", ctx, future)
		require.Error(t, err)
		require.Contains(t, err.Error(), "prefetch failed")
	})
}
