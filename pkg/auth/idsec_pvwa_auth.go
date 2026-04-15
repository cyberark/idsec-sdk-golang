package auth

import (
	"encoding/base64"
	"errors"
	"time"

	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth/pvwa"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

const (
	pvwaAuthName              = "pvwa"
	pvwaAuthHumanReadableName = "Password Vault Web Access"
)

// DefaultTokenLifetime is the default token lifetime in seconds for PVWA.
const (
	PVWADefaultTokenLifetime = 3600
)

var (
	pvwaAuthMethods               = []auth.IdsecAuthMethod{auth.PVWA}
	pvwaDefaultAuthMethod         = auth.PVWA
	pvwaDefaultAuthMethodSettings = auth.PVWAIdsecAuthMethodSettings{}
)

// IdsecPVWAAuth is a struct that implements the IdsecAuth interface for Password Vault Web Access.
type IdsecPVWAAuth struct {
	IdsecAuth
	*IdsecAuthBase
}

// NewIdsecPVWAAuth creates a new instance of IdsecPVWAAuth.
func NewIdsecPVWAAuth(cacheAuthentication bool) IdsecAuth {
	authenticator := &IdsecPVWAAuth{}
	var authInterface IdsecAuth = authenticator
	baseAuth := NewIdsecAuthBase(cacheAuthentication, "IdsecPVWAAuth", authInterface)
	authenticator.IdsecAuthBase = baseAuth
	return authInterface
}

func (a *IdsecPVWAAuth) constructMetadata(env commonmodels.AwsEnv, token string, cookieJar *cookiejar.Jar) (map[string]interface{}, error) {
	marshaledCookies, err := common.MarshalCookies(cookieJar)
	if err != nil {
		a.Logger.Error("Failed to marshal cookies: %v", err)
		return nil, err
	}
	metadata := map[string]interface{}{
		"env":     env,
		"cookies": base64.StdEncoding.EncodeToString(marshaledCookies),
	}
	return metadata, nil
}

func (a *IdsecPVWAAuth) performPVWAAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
	if secret == nil {
		return nil, errors.New("password secret is required for PVWA auth")
	}
	methodSettings := authProfile.AuthMethodSettings.(*auth.PVWAIdsecAuthMethodSettings)
	pvwaAuth, err := pvwa.NewIdsecPVWA(
		authProfile.Username,
		secret.Secret,
		methodSettings.PVWAURL,
		methodSettings.PVWALoginMethod,
		a.Logger,
		a.CacheAuthentication,
		!force,
		profile,
	)
	if err != nil {
		a.Logger.Error("Failed to create PVWA authentication object: %v", err)
		return nil, err
	}
	err = pvwaAuth.AuthPVWA(profile, force)
	if err != nil {
		a.Logger.Error("Failed to authenticate to PVWA: %v", err)
		return nil, err
	}
	metadata, err := a.constructMetadata(commonmodels.GetDeployEnv(), pvwaAuth.SessionToken(), pvwaAuth.Session().GetCookieJar())
	if err != nil {
		return nil, err
	}
	return &auth.IdsecToken{
		Token:      pvwaAuth.SessionToken(),
		Username:   authProfile.Username,
		Endpoint:   pvwaAuth.PVWAURL(),
		TokenType:  auth.Token,
		AuthMethod: auth.PVWA,
		ExpiresIn:  commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(PVWADefaultTokenLifetime) * time.Second)),
		Metadata:   metadata,
	}, nil
}

// performAuthentication performs authentication to PVWA using the specified auth method.
func (a *IdsecPVWAAuth) performAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
	a.Logger.Info("Performing authentication to PVWA")
	switch authProfile.AuthMethod {
	case auth.PVWA, auth.Default:
		return a.performPVWAAuthentication(profile, authProfile, secret, force)
	default:
		return nil, errors.New("given auth method is not supported")
	}
}

// performRefreshAuthentication performs refresh authentication to PVWA.
// PVWA doesn't support token refresh, so this returns the token unchanged.
func (a *IdsecPVWAAuth) performRefreshAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
	a.Logger.Info("Performing refresh authentication to PVWA")
	// PVWA doesn't support token refresh, return token unchanged
	return token, nil
}

// LoadAuthentication loads the authentication token from the cache or performs authentication if not found.
func (a *IdsecPVWAAuth) LoadAuthentication(profile *models.IdsecProfile, refreshAuth bool) (*auth.IdsecToken, error) {
	return a.IdsecAuthBase.LoadAuthentication(profile, refreshAuth)
}

// Authenticate performs authentication using the specified profile and authentication profile.
func (a *IdsecPVWAAuth) Authenticate(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, refreshAuth bool) (*auth.IdsecToken, error) {
	return a.IdsecAuthBase.Authenticate(profile, authProfile, secret, force, refreshAuth)
}

// IsAuthenticated checks if the user is authenticated using the specified profile.
func (a *IdsecPVWAAuth) IsAuthenticated(profile *models.IdsecProfile) bool {
	return a.IdsecAuthBase.IsAuthenticated(profile)
}

// AuthenticatorName returns the name of the PVWA authenticator.
func (a *IdsecPVWAAuth) AuthenticatorName() string {
	return pvwaAuthName
}

// AuthenticatorHumanReadableName returns the human-readable name of the PVWA authenticator.
func (a *IdsecPVWAAuth) AuthenticatorHumanReadableName() string {
	return pvwaAuthHumanReadableName
}

// SupportedAuthMethods returns the supported authentication methods for the PVWA authenticator.
func (a *IdsecPVWAAuth) SupportedAuthMethods() []auth.IdsecAuthMethod {
	return pvwaAuthMethods
}

// DefaultAuthMethod returns the default authentication method and its settings for the PVWA authenticator.
func (a *IdsecPVWAAuth) DefaultAuthMethod() (auth.IdsecAuthMethod, auth.IdsecAuthMethodSettings) {
	return pvwaDefaultAuthMethod, pvwaDefaultAuthMethodSettings
}
