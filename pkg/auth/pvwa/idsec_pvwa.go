package pvwa

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	authcommon "github.com/cyberark/idsec-sdk-golang/pkg/auth/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// getCacheKey generates a cache key for the given username.
// The cache key format is "{username}_pvwa".
func getCacheKey(username string) string {
	return username + "_pvwa"
}

// PVWAAuthAPIError represents an error response from the PVWA Auth API.
type PVWAAuthAPIError struct {
	ErrorCode    string `json:"ErrorCode"`
	ErrorMessage string `json:"ErrorMessage"`
}

// IdsecPVWA is a struct that represents a PVWA authentication session.
type IdsecPVWA struct {
	username            string
	password            string
	pvwaURL             string
	loginMethod         string
	logger              *common.IdsecLogger
	cacheAuthentication bool
	session             *common.IdsecClient
	sessionToken        string
	sessionExp          commonmodels.IdsecRFC3339Time
	keyring             keyring.IdsecKeyringInterface
	loadedFromCache     bool
	cacheManager        *authcommon.CacheManager
}

// NewIdsecPVWA creates a new IdsecPVWA instance with the specified parameters.
func NewIdsecPVWA(username string, password string, pvwaURL string, loginMethod string, logger *common.IdsecLogger, cacheAuthentication bool, loadCache bool, cacheProfile *models.IdsecProfile) (*IdsecPVWA, error) {
	if pvwaURL == "" {
		return nil, fmt.Errorf("pvwa URL is required")
	}
	if loginMethod == "" {
		return nil, fmt.Errorf("login method is required")
	}

	pvwaAuth := &IdsecPVWA{
		username:            username,
		password:            password,
		pvwaURL:             pvwaURL,
		loginMethod:         loginMethod,
		logger:              logger,
		cacheAuthentication: cacheAuthentication,
		loadedFromCache:     false,
	}

	pvwaAuth.session = common.NewSimpleIdsecClient(pvwaURL)
	pvwaAuth.session.SetHeaders(map[string]string{
		"Content-Type": "application/json",
	})

	if cacheAuthentication || loadCache {
		pvwaAuth.keyring = keyring.NewIdsecKeyring(strings.ToLower("IdsecPVWA"))
	}

	// Initialize cache manager
	cacheConfig := &authcommon.CacheConfig{
		Keyring:             pvwaAuth.keyring,
		CacheAuthentication: cacheAuthentication,
		Logger:              logger,
	}
	pvwaAuth.cacheManager = authcommon.NewCacheManager(cacheConfig)

	if loadCache && cacheProfile != nil {
		pvwaAuth.loadCache(cacheProfile)
	}

	return pvwaAuth, nil
}

func (a *IdsecPVWA) loadCache(profile *models.IdsecProfile) bool {
	if a.keyring != nil && profile != nil {
		token, err := a.keyring.LoadToken(profile, getCacheKey(a.username), false)
		if err != nil {
			a.logger.Error("Error loading token from cache: %v", err)
			return false
		}
		if token != nil && token.Username == a.username {
			a.sessionToken = token.Token
			a.sessionExp = token.ExpiresIn
			a.session.UpdateToken(a.sessionToken, "Bearer")
			a.loadedFromCache = true
			return true
		}
	}
	return false
}

func (a *IdsecPVWA) saveCache(profile *models.IdsecProfile) error {
	if a.keyring != nil && profile != nil && a.sessionToken != "" {
		err := a.keyring.SaveToken(profile, &auth.IdsecToken{
			Token:      a.sessionToken,
			Username:   a.username,
			Endpoint:   a.session.BaseURL,
			TokenType:  auth.Token,
			AuthMethod: auth.PVWA,
			ExpiresIn:  a.sessionExp,
		}, getCacheKey(a.username), false)
		if err != nil {
			return err
		}
	}
	return nil
}

// performPVWALogin performs the PVWA login request.
func (a *IdsecPVWA) performPVWALogin() (string, error) {
	logonPath := fmt.Sprintf("/PasswordVault/API/auth/%s/Logon/", a.loginMethod)

	body := map[string]string{
		"username": a.username,
		"password": a.password,
	}

	response, err := a.session.Post(context.Background(), logonPath, body)
	if err != nil {
		return "", err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			a.logger.Warning("Error closing response body")
		}
	}(response.Body)

	// Clear password from memory after use
	a.password = ""

	if response.StatusCode != http.StatusOK {
		var pvwaAuthError PVWAAuthAPIError
		if err := json.NewDecoder(response.Body).Decode(&pvwaAuthError); err != nil {
			return "", fmt.Errorf("failed to decode PVWA Auth API error response: %w", err)
		}
		return "", fmt.Errorf("%s %s", pvwaAuthError.ErrorCode, pvwaAuthError.ErrorMessage)
	}

	var token string
	if err := json.NewDecoder(response.Body).Decode(&token); err != nil {
		return "", err
	}

	if token == "" {
		return "", fmt.Errorf("invalid token response")
	}

	return token, nil
}

// AuthPVWA authenticates to PVWA with the information specified in the constructor.
// The auth token and other details are stored in the object for future use.
func (a *IdsecPVWA) AuthPVWA(profile *models.IdsecProfile, force bool) error {
	a.logger.Debug("Attempting to authenticate to PVWA")

	// Check cache if enabled and not forced
	if a.cacheManager.ShouldLoadFromCache(force, a.loadedFromCache) {
		if a.loadedFromCache {
			if a.cacheManager.ValidateCachedToken(a.sessionExp) {
				a.logger.Info("Loaded PVWA details from cache")
				return nil
			}
		} else {
			if a.loadCache(profile) {
				if a.cacheManager.ValidateCachedToken(a.sessionExp) {
					a.logger.Info("Loaded PVWA details from cache")
					return nil
				}
			}
		}
	}

	a.sessionToken = ""
	token, err := a.performPVWALogin()
	if err != nil {
		return err
	}

	a.sessionToken = token
	a.session.UpdateToken(token, "Bearer")

	// Set default token lifetime if not provided
	a.sessionExp = authcommon.CalculateExpirationTime(authcommon.DefaultTokenLifetimeSeconds)

	if a.cacheAuthentication {
		if err := a.saveCache(profile); err != nil {
			return err
		}
	}

	a.logger.Info("Successfully authenticated to PVWA")
	return nil
}

// Session returns the current PVWA session client.
func (a *IdsecPVWA) Session() *common.IdsecClient {
	return a.session
}

// SessionToken returns the current PVWA session token if logged in.
func (a *IdsecPVWA) SessionToken() string {
	return a.sessionToken
}

// PVWAURL returns the current PVWA URL.
func (a *IdsecPVWA) PVWAURL() string {
	return a.pvwaURL
}

// SessionExp returns the current PVWA session expiration time.
func (a *IdsecPVWA) SessionExp() commonmodels.IdsecRFC3339Time {
	return a.sessionExp
}
