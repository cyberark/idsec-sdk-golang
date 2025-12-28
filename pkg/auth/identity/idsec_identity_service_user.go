package identity

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

// IdsecIdentityServiceUser is a struct that represents identity authentication with service user.
type IdsecIdentityServiceUser struct {
	username            string
	token               string
	appName             string
	identityURL         string
	logger              *common.IdsecLogger
	keyring             keyring.IdsecKeyringInterface
	cacheAuthentication bool
	loadedFromCache     bool
	session             *common.IdsecClient
	sessionToken        string
	sessionExp          commonmodels.IdsecRFC3339Time
}

// NewIdsecIdentityServiceUser creates a new instance of IdsecIdentityServiceUser.
func NewIdsecIdentityServiceUser(username string, token string, appName string, identityURL string, identityTenantSubdomain string, logger *common.IdsecLogger, cacheAuthentication bool, loadCache bool, cacheProfile *models.IdsecProfile) (*IdsecIdentityServiceUser, error) {
	identityServiceAuth := &IdsecIdentityServiceUser{
		username:            username,
		token:               token,
		appName:             appName,
		identityURL:         identityURL,
		logger:              logger,
		cacheAuthentication: cacheAuthentication,
		loadedFromCache:     false,
	}
	var err error
	awsEnvObject, _ := commonmodels.GetAwsEnvFromList()
	if identityURL == "" {
		if identityTenantSubdomain != "" {
			identityURL, err = ResolveTenantFqdnFromTenantSubdomain(identityTenantSubdomain, awsEnvObject.RootDomain)
		} else {
			tenantSuffix := username[strings.Index(username, "@"):]
			identityURL, err = ResolveTenantFqdnFromTenantSuffix(tenantSuffix, awsEnvObject.IdentityEnvURL)
		}
	}
	if err != nil {
		return nil, err
	}
	identityServiceAuth.session = common.NewSimpleIdsecClient(identityURL)
	identityServiceAuth.session.SetHeaders(DefaultSystemHeaders())
	identityServiceAuth.session.SetHeader("Content-Type", "application/x-www-form-urlencoded")

	if cacheAuthentication || loadCache {
		identityServiceAuth.keyring = keyring.NewIdsecKeyring(strings.ToLower("IdsecIdentity"))
	}
	if loadCache && cacheProfile != nil {
		identityServiceAuth.loadCache(cacheProfile)
	}
	return identityServiceAuth, nil
}

func (ai *IdsecIdentityServiceUser) loadCache(profile *models.IdsecProfile) bool {
	if ai.keyring != nil && profile != nil {
		token, err := ai.keyring.LoadToken(profile, ai.username+"_identity_service_user", false)
		if err != nil {
			ai.logger.Error("Error loading token from cache: %v", err.Error())
			return false
		}
		if token != nil && token.Username == ai.username {
			ai.sessionToken = token.Token
			ai.sessionExp = token.ExpiresIn
			ai.session.UpdateToken(ai.sessionToken, "Bearer")
			ai.loadedFromCache = true
			return true
		}
	}
	return false
}

func (ai *IdsecIdentityServiceUser) saveCache(profile *models.IdsecProfile) error {
	if ai.keyring != nil && profile != nil && ai.sessionToken != "" {
		err := ai.keyring.SaveToken(profile, &auth.IdsecToken{
			Token:      ai.sessionToken,
			Username:   ai.username,
			Endpoint:   ai.session.BaseURL,
			TokenType:  auth.Internal,
			AuthMethod: auth.Other,
			ExpiresIn:  ai.sessionExp,
		}, ai.username+"_identity_service_user", false)
		if err != nil {
			return err
		}
	}
	return nil
}

// AuthIdentity Authenticates to Identity with a service user.
// This method creates an auth token and authorizes to the service.
func (ai *IdsecIdentityServiceUser) AuthIdentity(profile *models.IdsecProfile, force bool) error {
	ai.logger.Info("Authenticating to service user via endpoint [%s]", ai.identityURL)
	if ai.cacheAuthentication && !force {
		if ai.loadedFromCache {
			if time.Time(ai.sessionExp).After(time.Now()) {
				ai.logger.Info("Loaded identity service user details from cache")
				return nil
			}
		} else if ai.loadCache(profile) {
			if time.Time(ai.sessionExp).After(time.Now()) {
				ai.logger.Info("Loaded identity service user details from cache")
				return nil
			}
		}
	}
	ai.session.UpdateToken(
		base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", ai.username, ai.token))),
		"Basic",
	)
	response, err := ai.session.Post(
		context.Background(),
		fmt.Sprintf("OAuth2/Token/%s", ai.appName),
		map[string]string{
			"grant_type": "client_credentials",
			"scope":      "api",
		},
	)
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("failed logging in to identity service user")
	}

	var authResult map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&authResult); err != nil {
		return err
	}

	accessToken, ok := authResult["access_token"].(string)
	if !ok {
		return fmt.Errorf("failed logging in to identity service user, access token not found")
	}
	ai.session.UpdateToken(accessToken, "Bearer")
	ai.session.DisableRedirections()
	response, err = ai.session.Get(
		context.Background(),
		fmt.Sprintf("OAuth2/Authorize/%s", ai.appName),
		map[string]string{
			"client_id":     ai.appName,
			"response_type": "id_token",
			"scope":         "openid profile api",
			"redirect_uri":  "https://cyberark.cloud/redirect",
		},
	)
	ai.session.EnableRedirections()
	if err != nil {
		return err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)

	if response.StatusCode != http.StatusFound || response.Header.Get("Location") == "" {
		return fmt.Errorf("failed to authorize to application")
	}

	locationHeader := response.Header.Get("Location")
	locationHeaderSplitted := strings.Split(locationHeader, "#")
	if len(locationHeaderSplitted) != 2 {
		return fmt.Errorf("failed to parse location header to retrieve token from")
	}

	parsedQuery, err := url.ParseQuery(locationHeaderSplitted[1])
	if err != nil {
		return err
	}

	idTokens, ok := parsedQuery["id_token"]
	if !ok || len(idTokens) != 1 {
		return fmt.Errorf("failed to parse id token from location header")
	}

	ai.sessionToken = idTokens[0]

	// Try and decode exp from token
	newTokenClaims, _, err := new(jwt.Parser).ParseUnverified(ai.sessionToken, jwt.MapClaims{})
	if err != nil {
		return err
	}
	newClaims := newTokenClaims.Claims.(jwt.MapClaims)
	exp := int64(newClaims["exp"].(float64))
	iat := int64(newClaims["iat"].(float64))
	ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(int(exp-iat)) * time.Second))
	ai.session.UpdateToken(ai.sessionToken, "Bearer")
	ai.logger.Info("Created a service user session via endpoint [%s] with user [%s] to platform", ai.identityURL, ai.username)

	if ai.cacheAuthentication {
		if err := ai.saveCache(profile); err != nil {
			return err
		}
	}

	return nil
}

// Session returns the current identity session
func (ai *IdsecIdentityServiceUser) Session() *common.IdsecClient {
	return ai.session
}

// SessionToken returns the current identity session token if logged in
func (ai *IdsecIdentityServiceUser) SessionToken() string {
	return ai.sessionToken
}

// IdentityURL returns the current identity URL
func (ai *IdsecIdentityServiceUser) IdentityURL() string {
	return ai.session.BaseURL
}
