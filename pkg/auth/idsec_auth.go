package auth

import (
	"errors"
	"net/url"
	"slices"
	"sync"
	"time"

	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/profiles"

	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

const (
	defaultExpirationGraceDeltaSeconds = 60
)

// IdsecAuth is an interface that defines the methods for authentication in the Idsec SDK.
type IdsecAuth interface {
	// AuthenticatorName returns the name of the authenticator.
	AuthenticatorName() string
	// AuthenticatorHumanReadableName returns a human-readable name for the authenticator.
	AuthenticatorHumanReadableName() string
	// SupportedAuthMethods returns a list of supported authentication methods.
	SupportedAuthMethods() []auth.IdsecAuthMethod
	// IsAuthenticated checks if the authentication is already loaded for the specified profile.
	IsAuthenticated(profile *models.IdsecProfile) bool
	// DefaultAuthMethod returns the default authentication method and its settings.
	DefaultAuthMethod() (auth.IdsecAuthMethod, auth.IdsecAuthMethodSettings)
	// LoadAuthentication loads the authentication token for the specified profile and refreshes it if necessary.
	// It returns the authentication token and an error if any occurred.
	LoadAuthentication(profile *models.IdsecProfile, refreshAuth bool) (*auth.IdsecToken, error)
	// Authenticate performs authentication using the specified profile and authentication profile.
	// If profile is not passed (nil), will try to use the auth profile alone, but at least one of them needs to be passed
	// Secret may optionally be passed if needed for the authentication type
	// If force is true, it will force re-authentication even if a valid token is already present
	// If refreshAuth is true, it will attempt to refresh the token if it is expired
	// It returns the authentication token and an error if any occurred.
	Authenticate(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, refreshAuth bool) (*auth.IdsecToken, error)

	performAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool) (*auth.IdsecToken, error)
	performRefreshAuthentication(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, token *auth.IdsecToken) (*auth.IdsecToken, error)
}

// IdsecAuthBase is a struct that implements the IdsecAuth interface and provides common functionality for authentication.
//
// A single IdsecAuthBase instance may be shared across many goroutines (for example, the
// Terraform provider hands one shared authenticator to every resource and data source).
// All access to the Token/ActiveProfile/ActiveAuthProfile fields must therefore go through
// the synchronized accessors (GetToken/snapshotState/setState) rather than touching the
// fields directly. The stored *auth.IdsecToken is treated as immutable once published: it
// is always created fresh and swapped by pointer, never mutated in place.
type IdsecAuthBase struct {
	Authenticator       IdsecAuth
	Logger              *common.IdsecLogger
	CacheAuthentication bool
	CacheKeyring        keyring.IdsecKeyringInterface
	Token               *auth.IdsecToken
	ActiveProfile       *models.IdsecProfile
	ActiveAuthProfile   *auth.IdsecAuthProfile

	// stateMu guards reads/writes of Token, ActiveProfile and ActiveAuthProfile.
	// It is held only briefly so concurrent readers never block on network I/O.
	stateMu sync.RWMutex
	// opMu serializes auth/refresh operations (Authenticate, LoadAuthentication,
	// IsAuthenticated) so concurrent callers cannot interleave network refreshes
	// or publish a transiently-nil token to other goroutines.
	opMu sync.Mutex
}

// GetToken returns the current authentication token in a thread-safe manner.
// The returned *auth.IdsecToken is treated as immutable; callers must not mutate it.
// It may be nil if no valid token is currently loaded.
func (a *IdsecAuthBase) GetToken() *auth.IdsecToken {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.Token
}

// snapshotState returns a consistent snapshot of the current auth state under a read lock.
func (a *IdsecAuthBase) snapshotState() (*auth.IdsecToken, *models.IdsecProfile, *auth.IdsecAuthProfile) {
	a.stateMu.RLock()
	defer a.stateMu.RUnlock()
	return a.Token, a.ActiveProfile, a.ActiveAuthProfile
}

// setState atomically publishes the auth state. The token is always written (and may be
// nil to clear it); the active profile and auth profile are only updated when non-nil,
// preserving the prior behavior where they were retained unless a valid token was obtained.
func (a *IdsecAuthBase) setState(token *auth.IdsecToken, profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile) {
	a.stateMu.Lock()
	defer a.stateMu.Unlock()
	a.Token = token
	if profile != nil {
		a.ActiveProfile = profile
	}
	if authProfile != nil {
		a.ActiveAuthProfile = authProfile
	}
}

// NewIdsecAuthBase creates a new instance of IdsecAuthBase.
func NewIdsecAuthBase(cacheAuthentication bool, name string, authenticator IdsecAuth) *IdsecAuthBase {
	logger := common.GetLogger(name, common.Unknown)
	var cacheKeyring keyring.IdsecKeyringInterface
	if cacheAuthentication {
		cacheKeyring = keyring.NewIdsecKeyring(name)
	}
	return &IdsecAuthBase{
		Authenticator:       authenticator,
		Logger:              logger,
		CacheAuthentication: cacheAuthentication,
		CacheKeyring:        cacheKeyring,
	}
}

// ResolveCachePostfix resolves the cache postfix for the authentication profile.
func (a *IdsecAuthBase) ResolveCachePostfix(authProfile *auth.IdsecAuthProfile) string {
	postfix := authProfile.Username
	if authProfile.AuthMethod == auth.Direct && authProfile.AuthMethodSettings != nil {
		directMethodSettings := authProfile.AuthMethodSettings.(auth.DirectIdsecAuthMethodSettings)
		if directMethodSettings.Endpoint != "" {
			parsedURL, _ := url.Parse(directMethodSettings.Endpoint)
			postfix = postfix + "_" + parsedURL.Host
		}
	}
	return postfix
}

// Authenticate performs authentication using the specified profile and authentication profile.
func (a *IdsecAuthBase) Authenticate(profile *models.IdsecProfile, authProfile *auth.IdsecAuthProfile, secret *auth.IdsecSecret, force bool, refreshAuth bool) (*auth.IdsecToken, error) {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	if authProfile == nil && profile == nil {
		return nil, errors.New("either a profile or a specific auth profile must be supplied")
	}
	if authProfile == nil {
		if ap, ok := profile.AuthProfiles[a.Authenticator.AuthenticatorName()]; ok {
			authProfile = ap
		} else {
			return nil, errors.New(a.Authenticator.AuthenticatorHumanReadableName() + " [" + a.Authenticator.AuthenticatorName() + "] is not defined within the authentication profiles")
		}
	}
	if profile == nil {
		profilesLoader := profiles.DefaultProfilesLoader()
		profile, _ = (*profilesLoader).LoadDefaultProfile()
	}
	if !slices.Contains(a.Authenticator.SupportedAuthMethods(), authProfile.AuthMethod) && authProfile.AuthMethod != auth.Default {
		return nil, errors.New(a.Authenticator.AuthenticatorHumanReadableName() + " does not support authentication method " + string(authProfile.AuthMethod))
	}
	if authProfile.AuthMethod == auth.Default {
		authProfile.AuthMethod, authProfile.AuthMethodSettings = a.Authenticator.DefaultAuthMethod()
	}
	if slices.Contains(auth.IdsecAuthMethodsRequireCredentials, authProfile.AuthMethod) && authProfile.Username == "" {
		return nil, errors.New(a.Authenticator.AuthenticatorHumanReadableName() + " requires a username and optionally a secret")
	}
	var token *auth.IdsecToken
	var err error
	tokenRefreshed := false
	if a.CacheAuthentication && a.CacheKeyring != nil && !force {
		token, err = a.CacheKeyring.LoadToken(profile, a.ResolveCachePostfix(authProfile), false)
		if err != nil {
			return nil, err
		}
		if token != nil && time.Time(token.ExpiresIn).Before(time.Now()) {
			if refreshAuth && token.RefreshToken != "" {
				token, _ = a.Authenticator.performRefreshAuthentication(profile, authProfile, token)
				if token != nil {
					tokenRefreshed = true
				} else {
					token = nil
				}
			} else {
				token = nil
			}
		}
	}
	if token == nil {
		token, err = a.Authenticator.performAuthentication(profile, authProfile, secret, force)
		if err != nil {
			return nil, err
		}
		if token != nil && a.CacheAuthentication && a.CacheKeyring != nil {
			err := a.CacheKeyring.SaveToken(profile, token, a.ResolveCachePostfix(authProfile), false)
			if err != nil {
				return nil, err
			}
		}
	} else if refreshAuth && !tokenRefreshed {
		token, err = a.Authenticator.performRefreshAuthentication(profile, authProfile, token)
		if err != nil {
			return nil, err
		}
		if token != nil && a.CacheAuthentication && a.CacheKeyring != nil {
			err := a.CacheKeyring.SaveToken(profile, token, a.ResolveCachePostfix(authProfile), false)
			if err != nil {
				return nil, err
			}
		}
	}
	a.setState(token, profile, authProfile)
	return token, nil
}

// IsAuthenticated checks if the authentication is already loaded for the specified profile.
func (a *IdsecAuthBase) IsAuthenticated(profile *models.IdsecProfile) bool {
	a.opMu.Lock()
	defer a.opMu.Unlock()
	a.Logger.Info("Checking if [%s] is authenticated", a.Authenticator.AuthenticatorName())
	token, _, _ := a.snapshotState()
	if token != nil {
		a.Logger.Info("Token is already loaded")
		return true
	}
	if ap, ok := profile.AuthProfiles[a.Authenticator.AuthenticatorName()]; ok && a.CacheKeyring != nil {
		var err error
		token, err = a.CacheKeyring.LoadToken(profile, ap.Username, false)
		if err != nil {
			return false
		}
		if token != nil && time.Time(token.ExpiresIn).Before(time.Now()) {
			token = nil
		} else {
			a.Logger.Info("Loaded token from cache successfully")
		}
		a.setState(token, nil, nil)
		return token != nil
	}
	return false
}

// LoadAuthentication loads the authentication token for the specified profile and refreshes it if necessary.
//
// The token is computed into a local variable and published exactly once at the end so that
// concurrent readers (via GetToken) never observe a transiently-nil token while a cache load
// or network refresh is in progress.
func (a *IdsecAuthBase) LoadAuthentication(profile *models.IdsecProfile, refreshAuth bool) (*auth.IdsecToken, error) {
	a.opMu.Lock()
	defer a.opMu.Unlock()

	var err error
	a.Logger.Info("Trying to load [%s] authentication", a.Authenticator.AuthenticatorName())

	currentToken, activeProfile, activeAuthProfile := a.snapshotState()
	if profile == nil {
		if activeProfile != nil {
			profile = activeProfile
		} else {
			profilesLoader := profiles.DefaultProfilesLoader()
			profile, _ = (*profilesLoader).LoadDefaultProfile()
		}
	}
	authProfile := activeAuthProfile
	if authProfile == nil {
		if ap, ok := profile.AuthProfiles[a.Authenticator.AuthenticatorName()]; ok {
			authProfile = ap
		}
	}
	if authProfile == nil {
		return nil, nil
	}

	a.Logger.Info("Loading authentication for profile [%s] and auth profile [%s] of type [%s]", profile.ProfileName, a.Authenticator.AuthenticatorName(), string(authProfile.AuthMethod))

	// Seed from the currently loaded token so that, when no keyring is configured
	// (caching disabled), we keep the in-memory token instead of discarding it. The
	// keyring (when present) overwrites it, matching the original behavior where the
	// cache load only ran under `if a.CacheKeyring != nil`.
	token := currentToken
	if a.CacheKeyring != nil {
		token, err = a.CacheKeyring.LoadToken(profile, a.ResolveCachePostfix(authProfile), false)
		if err != nil {
			return nil, err
		}
	}
	if refreshAuth {
		if token != nil && time.Time(token.ExpiresIn).Add(-time.Duration(defaultExpirationGraceDeltaSeconds)*time.Second).After(time.Now()) {
			a.Logger.Info("Token did not pass grace expiration, no need to refresh")
		} else {
			a.Logger.Info("Trying to refresh token authentication")
			token, _ = a.Authenticator.performRefreshAuthentication(profile, authProfile, token)
			if token != nil && time.Time(token.ExpiresIn).After(time.Now()) {
				a.Logger.Info("Token refreshed")
			}
			if token != nil && a.CacheAuthentication && a.CacheKeyring != nil {
				err = a.CacheKeyring.SaveToken(profile, token, a.ResolveCachePostfix(authProfile), false)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	if token != nil && time.Time(token.ExpiresIn).Before(time.Now()) {
		token = nil
	}
	if token != nil {
		a.setState(token, profile, authProfile)
	} else {
		a.setState(nil, nil, nil)
	}
	return token, nil
}
