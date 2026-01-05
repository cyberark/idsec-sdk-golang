package auth

import (
	"encoding/base64"
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
	cookiejar "github.com/juju/persistent-cookiejar"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth/identity"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
)

const (
	ispAuthName              = "isp"
	ispAuthHumanReadableName = "Identity Security Platform"
)

// DefaultTokenLifetime is the default token lifetime in seconds.
const (
	DefaultTokenLifetime = 3600
)

var (
	ispAuthMethods               = []auth.IdsecAuthMethod{auth.Identity, auth.IdentityServiceUser}
	ispDefaultAuthMethod         = auth.Identity
	ispDefaultAuthMethodSettings = auth.IdentityIdsecAuthMethodSettings{}
)

// IdsecISPAuth is a struct that implements the IdsecAuth interface for the Identity Security Platform.
type IdsecISPAuth struct {
	IdsecAuth
	*IdsecAuthBase
}

// NewIdsecISPAuth creates a new instance of IdsecISPAuth.
func NewIdsecISPAuth(cacheAuthentication bool) IdsecAuth {
	authenticator := &IdsecISPAuth{}
	var authInterface IdsecAuth = authenticator
	baseAuth := NewIdsecAuthBase(cacheAuthentication, "IdsecISPAuth", authInterface)
	authenticator.IdsecAuthBase = baseAuth
	return authInterface
}

func (a *IdsecISPAuth) constructMetadata(env commonmodels.AwsEnv, token string, cookieJar *cookiejar.Jar) (map[string]interface{}, error) {
	marshaledCookies, err := common.MarshalCookies(cookieJar)
	if err != nil {
		a.Logger.Error("Failed to marshal cookies: %v", err)
		return nil, err
	}
	metadata := map[string]interface{}{
		"env":     env,
		"cookies": base64.StdEncoding.EncodeToString(marshaledCookies),
	}
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(token, jwt.MapClaims{})
	if err == nil {
		claims := parsedToken.Claims.(jwt.MapClaims)
		localTenantID, ok := claims["tenant_id"].(string)
		if ok {
			metadata["tenant_id"] = localTenantID
		}
		localSubdomain, ok := claims["subdomain"].(string)
		if ok {
			metadata["subdomain"] = localSubdomain
		}
	}
	return metadata, nil
}

func (a *IdsecISPAuth) performIdentityAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
	methodSettings := authProfile.AuthMethodSettings.(*auth.IdentityIdsecAuthMethodSettings)
	identityAuth, err := identity.NewIdsecIdentity(
		authProfile.Username,
		secret.Secret,
		methodSettings.IdentityURL,
		methodSettings.IdentityTenantSubdomain,
		methodSettings.IdentityMFAMethod,
		a.Logger,
		a.CacheAuthentication,
		!force,
		profile,
	)
	if err != nil {
		a.Logger.Error("Failed to create identity security platform object: %v", err)
		return nil, err
	}
	err = identityAuth.AuthIdentity(profile, config.IsInteractive() && methodSettings.IdentityMFAInteractive, force)
	if err != nil {
		a.Logger.Error("Failed to authenticate to identity security platform: %v", err)
		return nil, err
	}
	tokenLifetime := identityAuth.SessionDetails().TokenLifetime
	if tokenLifetime == 0 {
		tokenLifetime = DefaultTokenLifetime
	}
	metadata, err := a.constructMetadata(commonmodels.GetDeployEnv(), identityAuth.SessionToken(), identityAuth.Session().GetCookieJar())
	if err != nil {
		return nil, err
	}
	return &auth.IdsecToken{
		Token:        identityAuth.SessionToken(),
		Username:     authProfile.Username,
		Endpoint:     identityAuth.IdentityURL(),
		TokenType:    auth.JWT,
		AuthMethod:   auth.Identity,
		ExpiresIn:    commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(tokenLifetime) * time.Second)),
		RefreshToken: identityAuth.SessionDetails().RefreshToken,
		Metadata:     metadata,
	}, nil
}

func (a *IdsecISPAuth) performIdentityRefreshAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
	methodSettings := authProfile.AuthMethodSettings.(*auth.IdentityIdsecAuthMethodSettings)
	identityAuth, err := identity.NewIdsecIdentity(
		authProfile.Username,
		"",
		methodSettings.IdentityURL,
		methodSettings.IdentityTenantSubdomain,
		methodSettings.IdentityMFAMethod,
		a.Logger,
		a.CacheAuthentication,
		a.CacheAuthentication,
		profile,
	)
	if err != nil {
		a.Logger.Error("Failed to create identity security platform object: %v", err)
		return nil, err
	}
	err = identityAuth.RefreshAuthIdentity(profile, methodSettings.IdentityMFAInteractive, false)
	if err != nil {
		a.Logger.Error("Failed to refresh authentication to identity security platform: %v", err)
		return nil, err
	}
	tokenLifetime := identityAuth.SessionDetails().TokenLifetime
	if tokenLifetime == 0 {
		tokenLifetime = DefaultTokenLifetime
	}
	metadata, err := a.constructMetadata(commonmodels.GetDeployEnv(), identityAuth.SessionToken(), identityAuth.Session().GetCookieJar())
	if err != nil {
		return nil, err
	}
	return &auth.IdsecToken{
		Token:        identityAuth.SessionToken(),
		Username:     authProfile.Username,
		Endpoint:     identityAuth.IdentityURL(),
		TokenType:    auth.JWT,
		AuthMethod:   auth.Identity,
		ExpiresIn:    commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(tokenLifetime) * time.Second)),
		RefreshToken: identityAuth.SessionDetails().RefreshToken,
		Metadata:     metadata,
	}, nil
}

func (a *IdsecISPAuth) performIdentityServiceUserAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
	if secret == nil {
		return nil, errors.New("token secret is required for identity service user auth")
	}
	methodSettings := authProfile.AuthMethodSettings.(*auth.IdentityServiceUserIdsecAuthMethodSettings)
	identityAuth, err := identity.NewIdsecIdentityServiceUser(
		authProfile.Username,
		secret.Secret,
		methodSettings.IdentityAuthorizationApplication,
		methodSettings.IdentityURL,
		methodSettings.IdentityTenantSubdomain,
		a.Logger,
		a.CacheAuthentication,
		!force,
		profile,
	)
	if err != nil {
		a.Logger.Error("Failed to create identity security platform object with service user: %v", err)
		return nil, err
	}
	err = identityAuth.AuthIdentity(profile, force)
	if err != nil {
		a.Logger.Error("Failed to authenticate to identity security platform with service user: %v", err)
		return nil, err
	}
	metadata, err := a.constructMetadata(commonmodels.GetDeployEnv(), identityAuth.SessionToken(), identityAuth.Session().GetCookieJar())
	if err != nil {
		return nil, err
	}
	return &auth.IdsecToken{
		Token:      identityAuth.SessionToken(),
		Username:   authProfile.Username,
		Endpoint:   identityAuth.IdentityURL(),
		TokenType:  auth.JWT,
		AuthMethod: auth.Identity,
		ExpiresIn:  identityAuth.SessionExp(),
		Metadata:   metadata,
	}, nil
}

// performAuthentication performs authentication to the ISP using the specified auth method.
func (a *IdsecISPAuth) performAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error) {
	a.Logger.Info("Performing authentication to ISP")
	switch authProfile.AuthMethod {
	case auth.Identity, auth.Default:
		return a.performIdentityAuthentication(profile, authProfile, secret, force)
	case auth.IdentityServiceUser:
		return a.performIdentityServiceUserAuthentication(profile, authProfile, secret, force)
	default:
		return nil, errors.New("given auth method is not supported")
	}
}

// PerformRefreshAuthentication performs refresh authentication to the ISP.
func (a *IdsecISPAuth) performRefreshAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error) {
	a.Logger.Info("Performing refresh authentication to ISP")
	if authProfile.AuthMethod == auth.Identity || authProfile.AuthMethod == auth.Default {
		return a.performIdentityRefreshAuthentication(profile, authProfile, token)
	}
	return token, nil
}

// LoadAuthentication loads the authentication token from the cache or performs authentication if not found.
func (a *IdsecISPAuth) LoadAuthentication(profile *models.IdsecProfile, refreshAuth bool) (*auth.IdsecToken, error) {
	return a.IdsecAuthBase.LoadAuthentication(profile, refreshAuth)
}

// Authenticate performs authentication using the specified profile and authentication profile.
func (a *IdsecISPAuth) Authenticate(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, refreshAuth bool) (*auth.IdsecToken, error) {
	return a.IdsecAuthBase.Authenticate(profile, authProfile, secret, force, refreshAuth)
}

// IsAuthenticated checks if the user is authenticated using the specified profile.
func (a *IdsecISPAuth) IsAuthenticated(profile *models.IdsecProfile) bool {
	return a.IdsecAuthBase.IsAuthenticated(profile)
}

// AuthenticatorName returns the name of the ISP authenticator.
func (a *IdsecISPAuth) AuthenticatorName() string {
	return ispAuthName
}

// AuthenticatorHumanReadableName returns the human-readable name of the ISP authenticator.
func (a *IdsecISPAuth) AuthenticatorHumanReadableName() string {
	return ispAuthHumanReadableName
}

// SupportedAuthMethods returns the supported authentication methods for the ISP authenticator.
func (a *IdsecISPAuth) SupportedAuthMethods() []auth.IdsecAuthMethod {
	return ispAuthMethods
}

// DefaultAuthMethod returns the default authentication method and its settings for the ISP authenticator.
func (a *IdsecISPAuth) DefaultAuthMethod() (auth.IdsecAuthMethod, auth.IdsecAuthMethodSettings) {
	return ispDefaultAuthMethod, ispDefaultAuthMethodSettings
}
