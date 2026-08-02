package auth

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	identitymodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
)

const (
	keyringRecoveryHelperEnv = "IDSEC_KEYRING_RECOVERY_HELPER"
	keyringWriterHelperEnv   = "IDSEC_KEYRING_WRITER_HELPER"
)

func isolatedSubprocessEnvironment(overrides map[string]string) []string {
	env := make([]string, 0, len(os.Environ())+len(overrides))
	for _, entry := range os.Environ() {
		key, _, _ := strings.Cut(entry, "=")
		if _, overridden := overrides[key]; !overridden {
			env = append(env, entry)
		}
	}
	for key, value := range overrides {
		env = append(env, key+"="+value)
	}
	return env
}

func saveIdentityKeyringState(
	t *testing.T,
	profile *models.IdsecProfile,
	username string,
	endpoint string,
	token string,
	refreshToken string,
	expiresAt commonmodels.IdsecRFC3339Time,
) {
	t.Helper()

	sessionDetails, err := json.Marshal(identitymodels.AdvanceAuthResult{
		Token:         token,
		RefreshToken:  refreshToken,
		TokenLifetime: int(time.Until(time.Time(expiresAt)).Seconds()),
	})
	if err != nil {
		t.Fatalf("failed to marshal Identity session details: %v", err)
	}
	sessionInfo, err := json.Marshal(map[string]interface{}{
		"headers": map[string]string{},
		"cookies": map[string]string{},
	})
	if err != nil {
		t.Fatalf("failed to marshal Identity session: %v", err)
	}

	identityKeyring := keyring.NewIdsecKeyring(strings.ToLower("IdsecIdentity"))
	if err := identityKeyring.SaveToken(profile, &authmodels.IdsecToken{
		Token:     string(sessionDetails),
		Username:  username,
		ExpiresIn: expiresAt,
	}, username+"_identity", true); err != nil {
		t.Fatalf("failed to save Identity token state: %v", err)
	}
	if err := identityKeyring.SaveToken(profile, &authmodels.IdsecToken{
		Token:     string(sessionInfo),
		Username:  username,
		Endpoint:  endpoint,
		ExpiresIn: expiresAt,
	}, username+"_identity_session", true); err != nil {
		t.Fatalf("failed to save Identity session state: %v", err)
	}
}

// TestIdentityRefreshRecoversFromConcurrentKeyringRotation verifies the
// cross-process recovery branch with a real, isolated file-backed keyring. A
// subprocess prevents its keyring environment from interfering with parallel
// package tests.
func TestIdentityRefreshRecoversFromConcurrentKeyringRotation(t *testing.T) {
	command := exec.Command(
		os.Args[0],
		"-test.run=^TestIdentityRefreshRecoversFromConcurrentKeyringRotationSubprocess$",
		"-test.v",
	)
	command.Env = isolatedSubprocessEnvironment(map[string]string{
		keyringRecoveryHelperEnv: "true",
		"IDSEC_BASIC_KEYRING":    "true",
		"IDSEC_KEYRING_FOLDER":   t.TempDir(),
	})

	output, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("keyring-recovery subprocess failed: %v\n%s", err, output)
	}
}

func TestIdentityRefreshRecoversFromConcurrentKeyringRotationSubprocess(t *testing.T) {
	if os.Getenv(keyringRecoveryHelperEnv) != "true" {
		t.Skip("subprocess helper")
	}

	const username = "regular-user@test.com"
	initialToken := serviceUserTestIDToken(t, "initial-keyring-state")
	rotatedToken := serviceUserTestIDToken(t, "rotated-keyring-state")
	rotatedExpiration := commonmodels.IdsecRFC3339Time(time.Now().Add(time.Hour))
	requestStarted := make(chan struct{})
	releaseRequest := make(chan struct{})
	var requestStartedOnce sync.Once
	var refreshRequests atomic.Int32

	identityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/OAuth2/RefreshPlatformToken" {
			http.NotFound(w, r)
			return
		}
		refreshRequests.Add(1)
		requestStartedOnce.Do(func() {
			close(requestStarted)
		})
		<-releaseRequest
		http.Error(w, "stale rotating refresh token", http.StatusUnauthorized)
	}))
	defer identityServer.Close()

	profile := CreateTestProfile("keyring-recovery", "isp", username)
	authProfile := &authmodels.IdsecAuthProfile{
		Username:   username,
		AuthMethod: authmodels.Identity,
		AuthMethodSettings: &authmodels.IdentityIdsecAuthMethodSettings{
			IdentityURL: identityServer.URL,
		},
	}
	saveIdentityKeyringState(
		t,
		profile,
		username,
		identityServer.URL,
		initialToken,
		"initial-refresh-token",
		commonmodels.IdsecRFC3339Time(time.Now().Add(time.Hour)),
	)

	authenticator := NewIdsecISPAuth(true).(*IdsecISPAuth)
	resultChannel := make(chan *authmodels.IdsecToken, 1)
	errorChannel := make(chan error, 1)
	go func() {
		result, err := authenticator.performIdentityRefreshAuthentication(
			profile,
			authProfile,
			&authmodels.IdsecToken{
				Token:        initialToken,
				Username:     username,
				Endpoint:     identityServer.URL,
				AuthMethod:   authmodels.Identity,
				ExpiresIn:    commonmodels.IdsecRFC3339Time(time.Now().Add(-time.Minute)),
				RefreshToken: "initial-refresh-token",
			},
		)
		resultChannel <- result
		errorChannel <- err
	}()

	select {
	case <-requestStarted:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for stale refresh request")
	}

	// A separate process completes token rotation while this process still has
	// the prior refresh state in flight.
	writer := exec.Command(
		os.Args[0],
		"-test.run=^TestIdentityKeyringRotationWriterSubprocess$",
		"-test.v",
	)
	writer.Env = isolatedSubprocessEnvironment(map[string]string{
		keyringWriterHelperEnv:        "true",
		"IDSEC_KEYRING_PROFILE":       profile.ProfileName,
		"IDSEC_KEYRING_USERNAME":      username,
		"IDSEC_KEYRING_ENDPOINT":      identityServer.URL,
		"IDSEC_KEYRING_TOKEN":         rotatedToken,
		"IDSEC_KEYRING_REFRESH_TOKEN": "rotated-refresh-token",
		"IDSEC_KEYRING_EXPIRES_AT":    time.Time(rotatedExpiration).Format(time.RFC3339Nano),
	})
	if output, err := writer.CombinedOutput(); err != nil {
		close(releaseRequest)
		t.Fatalf("keyring writer subprocess failed: %v\n%s", err, output)
	}
	close(releaseRequest)

	var result *authmodels.IdsecToken
	select {
	case result = <-resultChannel:
	case <-time.After(5 * time.Second):
		t.Fatal("timed out waiting for keyring recovery")
	}
	if err := <-errorChannel; err != nil {
		t.Fatalf("expected recovery from rotated keyring state, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected recovered token")
	}
	if result.Token != rotatedToken {
		t.Fatalf("expected rotated keyring token, got %q", result.Token)
	}
	if result.RefreshToken != "rotated-refresh-token" {
		t.Fatalf("expected rotated refresh token, got %q", result.RefreshToken)
	}
	if refreshRequests.Load() != 1 {
		t.Fatalf("expected one failed refresh before keyring recovery, got %d", refreshRequests.Load())
	}
}

func TestIdentityKeyringRotationWriterSubprocess(t *testing.T) {
	if os.Getenv(keyringWriterHelperEnv) != "true" {
		t.Skip("subprocess helper")
	}

	expiresAt, err := time.Parse(time.RFC3339Nano, os.Getenv("IDSEC_KEYRING_EXPIRES_AT"))
	if err != nil {
		t.Fatalf("failed to parse keyring expiration: %v", err)
	}
	profileName := os.Getenv("IDSEC_KEYRING_PROFILE")
	if profileName == "" {
		t.Fatal("keyring profile name is required")
	}
	saveIdentityKeyringState(
		t,
		&models.IdsecProfile{ProfileName: profileName},
		os.Getenv("IDSEC_KEYRING_USERNAME"),
		os.Getenv("IDSEC_KEYRING_ENDPOINT"),
		os.Getenv("IDSEC_KEYRING_TOKEN"),
		os.Getenv("IDSEC_KEYRING_REFRESH_TOKEN"),
		commonmodels.IdsecRFC3339Time(expiresAt),
	)
}
