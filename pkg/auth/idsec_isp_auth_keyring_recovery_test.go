package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
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
	keyringLeftoverStateEnv  = "IDSEC_KEYRING_LEFTOVER_STATE"

	// leftoverUninterpretableContents names keyring state that is not a keyring at all.
	leftoverUninterpretableContents = "uninterpretable_contents"
	// leftoverEarlierFormat names keyring state written in an earlier on-disk format.
	leftoverEarlierFormat = "earlier_on_disk_format"
)

// isolatedKeyringEnvironment returns the given overrides alongside the ones that keep
// a subprocess keyring, including the master secret it derives its keys from, inside
// the test's own folders.
//
// Both keyring variables are needed. The master secret deliberately lives outside the
// keyring folder, so overriding the folder alone leaves the subprocess writing key
// material into the home directory of whoever is running the suite.
func isolatedKeyringEnvironment(t *testing.T, overrides map[string]string) map[string]string {
	t.Helper()

	environment := map[string]string{
		"IDSEC_BASIC_KEYRING":                  "true",
		keyring.IdsecBasicKeyringFolderEnvVar:  t.TempDir(),
		keyring.IdsecBasicKeyringKeyFileEnvVar: filepath.Join(t.TempDir(), "keyring.key"),
	}
	for key, value := range overrides {
		environment[key] = value
	}
	return environment
}

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
	command.Env = isolatedSubprocessEnvironment(isolatedKeyringEnvironment(t, map[string]string{
		keyringRecoveryHelperEnv: "true",
	}))

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

// TestIdentityRefreshRecoversFromUnreadableKeyringState verifies that cached
// Identity state which can no longer be read does not fail a refresh. The refresh
// re-authenticates against Identity instead, using the same isolated file-backed
// keyring and subprocess pairing as the rotation case.
//
// The cases cover both shapes such state takes in practice: content that is not a
// keyring at all, and a keyring written in an earlier on-disk format that this build
// no longer reads.
func TestIdentityRefreshRecoversFromUnreadableKeyringState(t *testing.T) {
	tests := []struct {
		name          string
		leftoverState string
	}{
		{name: "success_uninterpretable_contents", leftoverState: leftoverUninterpretableContents},
		{name: "success_earlier_on_disk_format", leftoverState: leftoverEarlierFormat},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			command := exec.Command(
				os.Args[0],
				"-test.run=^TestIdentityRefreshRecoversFromUnreadableKeyringStateSubprocess$",
				"-test.v",
			)
			command.Env = isolatedSubprocessEnvironment(isolatedKeyringEnvironment(t, map[string]string{
				keyringRecoveryHelperEnv: "true",
				keyringLeftoverStateEnv:  tt.leftoverState,
			}))

			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("keyring-recovery subprocess failed: %v\n%s", err, output)
			}
		})
	}
}

func TestIdentityRefreshRecoversFromUnreadableKeyringStateSubprocess(t *testing.T) {
	if os.Getenv(keyringRecoveryHelperEnv) != "true" {
		t.Skip("subprocess helper")
	}

	const username = "regular-user@test.com"
	const refreshedRefreshToken = "refreshed-refresh-token"
	initialToken := serviceUserTestIDToken(t, "initial-keyring-state")
	refreshedToken := serviceUserTestIDToken(t, "refreshed-keyring-state")

	identityServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/OAuth2/RefreshPlatformToken" {
			http.NotFound(w, r)
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:  "idToken-test-tenant-id",
			Value: refreshedToken,
			Path:  "/",
		})
		http.SetCookie(w, &http.Cookie{
			Name:  "refreshToken-test-tenant-id",
			Value: refreshedRefreshToken,
			Path:  "/",
		})
		w.WriteHeader(http.StatusOK)
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

	// A separate process leaves behind keyring state that can no longer be read.
	writer := exec.Command(
		os.Args[0],
		"-test.run=^TestIdentityKeyringLeftoverStateWriterSubprocess$",
		"-test.v",
	)
	writer.Env = isolatedSubprocessEnvironment(map[string]string{
		keyringWriterHelperEnv: "true",
	})
	if output, err := writer.CombinedOutput(); err != nil {
		t.Fatalf("keyring writer subprocess failed: %v\n%s", err, output)
	}
	// The writer runs against the same isolated folder, so the state it left behind is
	// the state this process is about to read.
	leftoverState := filepath.Join(os.Getenv(keyring.IdsecBasicKeyringFolderEnvVar), "keyring")
	if _, err := os.Stat(leftoverState); err != nil {
		t.Fatalf("expected leftover keyring state to be in place: %v", err)
	}

	authenticator := NewIdsecISPAuth(true).(*IdsecISPAuth)
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
	if err != nil {
		t.Fatalf("expected re-authentication after unreadable keyring state, got: %v", err)
	}
	if result == nil {
		t.Fatal("expected a re-authenticated token")
	}
	if result.Token != refreshedToken {
		t.Fatalf("expected re-authenticated token, got %q", result.Token)
	}
	if result.RefreshToken != refreshedRefreshToken {
		t.Fatalf("expected re-authenticated refresh token, got %q", result.RefreshToken)
	}
}

func TestIdentityKeyringLeftoverStateWriterSubprocess(t *testing.T) {
	if os.Getenv(keyringWriterHelperEnv) != "true" {
		t.Skip("subprocess helper")
	}

	folder := os.Getenv(keyring.IdsecBasicKeyringFolderEnvVar)
	if folder == "" {
		t.Fatal("keyring folder is required")
	}
	if os.Getenv(keyringLeftoverStateEnv) == leftoverEarlierFormat {
		writeEarlierFormatKeyringState(t, folder)
		return
	}
	if err := os.WriteFile(filepath.Join(folder, "keyring"), []byte("this is not keyring content"), 0600); err != nil {
		t.Fatalf("failed to write keyring state: %v", err)
	}
}

// writeEarlierFormatKeyringState leaves behind a keyring in the on-disk layout an
// earlier build used: a flat map of records carrying no format version, and a
// separate file holding a digest of it.
//
// This build recognises the file by its format and discards it before any record is
// read, so the records are left opaque here.
func writeEarlierFormatKeyringState(t *testing.T, folder string) {
	t.Helper()

	opaque := base64.StdEncoding.EncodeToString([]byte("record bytes this build never reads"))
	data, err := json.Marshal(map[string]map[string]map[string]string{
		"keyring-recovery": {
			"idsecidentity-regular-user@test.com_identity": {
				"nonce":      opaque,
				"ciphertext": opaque,
				"tag":        opaque,
			},
		},
	})
	if err != nil {
		t.Fatalf("failed to encode earlier-format keyring state: %v", err)
	}
	if err := os.WriteFile(filepath.Join(folder, "keyring"), data, 0600); err != nil {
		t.Fatalf("failed to write earlier-format keyring state: %v", err)
	}
	digest := sha256.Sum256(data)
	if err := os.WriteFile(filepath.Join(folder, "mac"), []byte(hex.EncodeToString(digest[:])), 0600); err != nil {
		t.Fatalf("failed to write earlier-format keyring digest: %v", err)
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
