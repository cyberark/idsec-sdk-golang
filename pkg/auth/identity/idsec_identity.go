package identity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"time"

	survey "github.com/Iilun/survey/v2"
	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/toqueteos/webbrowser"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/keyring"
	"github.com/cyberark/idsec-sdk-golang/pkg/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
	commonmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/models/common/identity"
)

const (
	recvRoutineInterval           = 3 * time.Second
	msPollInterval                = 500 * time.Millisecond
	secondsPollTime               = 360 * time.Second
	secondsLastStartAuthRespDelta = 30 * time.Second
	mechanismRetryCount           = 20
)

// DefaultTokenLifetimeSeconds is the default token lifetime in seconds.
const (
	DefaultTokenLifetimeSeconds = 3600
)

var factors = map[string]string{
	"otp":   "📲 Push / Code",
	"oath":  "🔐 OATH Code",
	"sms":   "📟 SMS",
	"email": "📧 Email",
	"pf":    "📞 Phone call",
	"up":    "🔑 User Password",
}

type lastStartAuthResponse struct {
	lastResponse *identity.StartAuthResponse
	timestamp    time.Time
	cookies      map[string]string
}

var lastStartAuthResponses = make(map[string]*lastStartAuthResponse)

var supportedIdentityMechanisms = []string{"pf", "sms", "email", "otp", "oath", "up"}

// IdsecIdentity is a struct that represents an identity authentication session.
type IdsecIdentity struct {
	username            string
	password            string
	mfaType             string
	logger              *common.IdsecLogger
	cacheAuthentication bool
	session             *common.IdsecClient
	sessionDetails      *identity.AdvanceAuthResult
	sessionExp          commonmodels.IdsecRFC3339Time
	keyring             keyring.IdsecKeyringInterface
	isPolling           bool
	loadedFromCache     bool
	interactionRoutine  chan string
}

// HasCacheRecord Checks if a cache record exists for the specified profile and username
func HasCacheRecord(profile *models.IdsecProfile, username string, refreshAuthAllowed bool) (bool, error) {
	keyring := keyring.NewIdsecKeyring(strings.ToLower("IdsecIdentity"))
	token, err := keyring.LoadToken(profile, username+"_identity", false)
	if err != nil {
		return false, err
	}
	session, err := keyring.LoadToken(profile, username+"_identity_session", false)
	if err != nil {
		return false, err
	}
	if token != nil && session != nil {
		if !time.Time(token.ExpiresIn).IsZero() && time.Time(token.ExpiresIn).Before(time.Now()) {
			if token.RefreshToken != "" && refreshAuthAllowed {
				return true, nil
			}
			return false, nil
		}
		return true, nil
	}
	return false, nil
}

// IsIdpUser Checks whether or not the specified username is from an external IDP
func IsIdpUser(username string, identityURL *string, identityTenantSubdomain *string) (bool, error) {
	matched, err := regexp.MatchString(`.*@cyberark\.cloud\.\d+`, username)
	if err != nil {
		return false, err
	}
	if matched {
		return false, nil
	}

	ai, err := NewIdsecIdentity(username, "", *identityURL, *identityTenantSubdomain, "", common.GetLogger("IsIdpUser", common.Unknown), false, false, nil)
	if err != nil {
		return false, err
	}

	resp, err := ai.startAuthentication()
	if err != nil {
		return false, err
	}

	return resp.Result.IdpRedirectURL != "", nil
}

// IsPasswordRequired Checks if a password is required for the specified username
func IsPasswordRequired(username string, identityURL string, identityTenantSubdomain string) bool {
	ai, err := NewIdsecIdentity(username, "", identityURL, identityTenantSubdomain, "", common.GetLogger("IsPasswordRequired", common.Unknown), false, false, nil)
	if err != nil {
		return true
	}
	resp, err := ai.startAuthentication()
	if err != nil {
		return true
	}
	if !resp.Success {
		return true
	}
	lastStartAuthResponses[fmt.Sprintf("%s_%s", ai.IdentityURL(), username)] = &lastStartAuthResponse{
		lastResponse: resp,
		timestamp:    time.Now(),
		cookies:      ai.session.GetCookies(),
	}
	return resp.Result.IdpRedirectURL == "" && len(resp.Result.Challenges) > 0 && resp.Result.Challenges[0].Mechanisms[0].Name == "UP"
}

// NewIdsecIdentity creates a new IdsecIdentity instance with the specified parameters.
func NewIdsecIdentity(username string, password string, identityURL string, identityTenantSubdomain string, mfaType string, logger *common.IdsecLogger, cacheAuthentication bool, loadCache bool, cacheProfile *models.IdsecProfile) (*IdsecIdentity, error) {
	var err error
	if mfaType == "" {
		mfaType = "email"
	}
	awsEnvObject, _ := commonmodels.GetAwsEnvFromList()
	identityAuth := &IdsecIdentity{
		username:            username,
		password:            password,
		mfaType:             mfaType,
		logger:              logger,
		cacheAuthentication: cacheAuthentication,
		isPolling:           false,
		loadedFromCache:     false,
	}

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
	identityAuth.session = common.NewSimpleIdsecClient(identityURL)
	identityAuth.session.SetHeaders(DefaultHeaders())

	if cacheAuthentication || loadCache {
		identityAuth.keyring = keyring.NewIdsecKeyring(strings.ToLower("IdsecIdentity"))
	}

	if loadCache && cacheProfile != nil {
		identityAuth.loadCache(cacheProfile)
	}
	return identityAuth, nil
}

func (ai *IdsecIdentity) loadCache(profile *models.IdsecProfile) bool {
	if ai.keyring != nil && profile != nil {
		token, err := ai.keyring.LoadToken(profile, ai.username+"_identity", false)
		if err != nil {
			ai.logger.Error("Error loading token from cache: %v", err)
			return false
		}
		session, err := ai.keyring.LoadToken(profile, ai.username+"_identity_session", false)
		if err != nil {
			ai.logger.Error("Error loading session from cache: %v", err)
			return false
		}
		if token != nil && session != nil {
			err = json.Unmarshal([]byte(token.Token), &ai.sessionDetails)
			if err != nil {
				return false
			}
			ai.sessionExp = token.ExpiresIn
			sessionInfo := map[string]interface{}{}
			err = json.Unmarshal([]byte(session.Token), &sessionInfo)
			if err != nil {
				return false
			}
			ai.session = common.NewSimpleIdsecClient(session.Endpoint)
			headers := make(map[string]string)
			for k, v := range sessionInfo["headers"].(map[string]interface{}) {
				headers[k] = v.(string)
			}
			ai.session.SetHeaders(headers)

			cookies := make(map[string]string)
			for k, v := range sessionInfo["cookies"].(map[string]interface{}) {
				cookies[k] = v.(string)
			}
			ai.session.SetCookies(cookies)
			ai.session.UpdateToken(ai.sessionDetails.Token, "Bearer")
			ai.loadedFromCache = true
			return true
		}
	}
	return false
}

func (ai *IdsecIdentity) saveCache(profile *models.IdsecProfile) error {
	if ai.keyring != nil && profile != nil && ai.sessionDetails != nil {
		delta := ai.sessionDetails.TokenLifetime
		if delta == 0 {
			delta = DefaultTokenLifetimeSeconds
		}
		ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(delta) * time.Second))
		sessionDetailsBytes, err := json.Marshal(ai.sessionDetails)
		if err != nil {
			return err
		}
		err = ai.keyring.SaveToken(profile, &auth.IdsecToken{
			Token:      string(sessionDetailsBytes),
			Username:   ai.username,
			Endpoint:   ai.session.BaseURL,
			TokenType:  auth.Internal,
			AuthMethod: auth.Other,
			ExpiresIn:  ai.sessionExp,
		}, ai.username+"_identity", false)
		if err != nil {
			return err
		}
		sessionInfo := map[string]interface{}{
			"headers": ai.session.GetHeaders(),
			"cookies": ai.session.GetCookies(),
		}
		sessionInfoBytes, err := json.Marshal(sessionInfo)
		if err != nil {
			return err
		}
		err = ai.keyring.SaveToken(profile, &auth.IdsecToken{
			Token:      string(sessionInfoBytes),
			Username:   ai.username,
			Endpoint:   ai.session.BaseURL,
			TokenType:  auth.Internal,
			AuthMethod: auth.Other,
			ExpiresIn:  ai.sessionExp,
		}, ai.username+"_identity_session", false)
		if err != nil {
			return err
		}
	}
	return nil
}

func (ai *IdsecIdentity) startAuthentication() (*identity.StartAuthResponse, error) {
	ai.logger.Info("Starting authentication with user %s and fqdn %s", ai.username, ai.session.BaseURL)
	response, err := ai.session.Post(
		context.Background(),
		"Security/StartAuthentication",
		map[string]interface{}{
			"User":                  ai.username,
			"Version":               "1.0",
			"PlatformTokenResponse": true,
			"AssociatedEntityType":  "API",
			"MfaRequestor":          "DeviceAgent",
		},
	)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)

	var parsedRes identity.StartAuthResponse
	if err = json.NewDecoder(response.Body).Decode(&parsedRes); err != nil {
		return nil, err
	}
	if !parsedRes.Success {
		return nil, errors.New("failed to start authentication")
	}
	if len(parsedRes.Result.Challenges) == 0 && parsedRes.Result.IdpRedirectURL == "" {
		return nil, errors.New("no challenges or idp redirect url on start auth")
	}

	return &parsedRes, nil
}

func (ai *IdsecIdentity) advanceAuthentication(mechanismID string, sessionID string, answer string, action string, isIdpAuth bool) (interface{}, error) {
	ai.logger.Info("Advancing authentication with action %s", action)
	response, err := ai.session.Post(
		context.Background(),
		"Security/AdvanceAuthentication",
		map[string]interface{}{
			"SessionId":   sessionID,
			"MechanismId": mechanismID,
			"Action":      action,
			"Answer":      answer,
		},
	)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	if isIdpAuth {
		var finalRes identity.IdpAuthStatusResponse
		if err = json.Unmarshal(bodyBytes, &finalRes); err != nil {
			return nil, err
		}
		return &finalRes, nil
	}
	var parsedRes identity.AdvanceAuthMidResponse
	if err = json.Unmarshal(bodyBytes, &parsedRes); err != nil {
		return nil, err
	}
	if parsedRes.Result.Summary == "LoginSuccess" {
		var finalRes identity.AdvanceAuthResponse
		if err = json.Unmarshal(bodyBytes, &finalRes); err != nil {
			return nil, err
		}
		return &finalRes, nil
	}
	return &parsedRes, nil
}

func (ai *IdsecIdentity) identityIdpAuthStatus(sessionID string) (*identity.IdpAuthStatusResponse, error) {
	ai.logger.Info("Checking identity idp authentication status with session %s", sessionID)
	response, err := ai.session.Post(
		context.Background(),
		"Security/OobAuthStatus",
		map[string]interface{}{
			"SessionId": sessionID,
		},
	)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)
	bodyBytes, err := io.ReadAll(response.Body)
	if err != nil {
		return nil, err
	}
	var parsedRes identity.IdpAuthStatusResponse
	if err := json.Unmarshal(bodyBytes, &parsedRes); err != nil {
		return nil, err
	}
	return &parsedRes, nil
}

func (ai *IdsecIdentity) performPinCodeIdpAuthentication(startAuthResponse *identity.StartAuthResponse, profile *models.IdsecProfile, interactive bool) error {
	if !interactive {
		return errors.New("non-interactive mode is not supported for OOB PIN code authentication")
	}
	var answer string
	prompt := &survey.Password{
		Message: "Please enter the PIN code displayed after you logged in to your identity provider",
	}
	err := survey.AskOne(prompt, &answer)
	if err != nil {
		return err
	}
	if answer == "" {
		return errors.New("PIN code cannot be empty")
	}
	oobAdvanceResp, err := ai.advanceAuthentication("OOBAUTHPIN", startAuthResponse.Result.IdpLoginSessionID, answer, "Answer", true)
	if err != nil {
		return err
	}
	if !oobAdvanceResp.(*identity.IdpAuthStatusResponse).Success {
		return errors.New("failed to perform idp authentication with OOB PIN")
	}
	if oobAdvanceResp.(*identity.IdpAuthStatusResponse).Result.Summary == "LoginSuccess" && oobAdvanceResp.(*identity.IdpAuthStatusResponse).Result.Token != "" {
		ai.sessionDetails = &identity.AdvanceAuthResult{
			Token:         oobAdvanceResp.(*identity.IdpAuthStatusResponse).Result.Token,
			TokenLifetime: oobAdvanceResp.(*identity.IdpAuthStatusResponse).Result.TokenLifetime,
			RefreshToken:  oobAdvanceResp.(*identity.IdpAuthStatusResponse).Result.RefreshToken,
		}
		ai.session.UpdateToken(oobAdvanceResp.(*identity.IdpAuthStatusResponse).Result.Token, "Bearer")
		delta := ai.sessionDetails.TokenLifetime
		if delta == 0 {
			delta = DefaultTokenLifetimeSeconds
		}
		ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(delta) * time.Second))
		if ai.cacheAuthentication {
			if err := ai.saveCache(profile); err != nil {
				return err
			}
		}
		return nil
	}
	return errors.New("failed to perform idp authentication with OOB PIN, please try again")
}

func (ai *IdsecIdentity) performIdpAuthentication(startAuthResponse *identity.StartAuthResponse, profile *models.IdsecProfile, interactive bool) error {
	if ai.isPolling {
		return errors.New("MFA / IDP Polling is already in progress")
	}
	if interactive {
		fmt.Printf("\nYou are now being redirected from your browser to your external identity provider for authentication\n"+
			"If the browser did not open, you may also click the following URL to access your identity provider authentication\n\n"+
			"%s\n", startAuthResponse.Result.IdpRedirectShortURL)
	}

	// Error can be ignored
	_ = webbrowser.Open(startAuthResponse.Result.IdpRedirectShortURL)

	if startAuthResponse.Result.IdpOobAuthPinRequired {
		return ai.performPinCodeIdpAuthentication(startAuthResponse, profile, interactive)
	}

	ai.isPolling = true
	startTime := time.Now()

	for ai.isPolling {
		currentTime := time.Now()
		if currentTime.Sub(startTime) >= secondsPollTime {
			ai.isPolling = false
			return errors.New("timeout reached while polling for idp auth")
		}

		idpAuthStatus, err := ai.identityIdpAuthStatus(startAuthResponse.Result.IdpLoginSessionID)
		if err != nil {
			return err
		}
		if !idpAuthStatus.Success {
			return errors.New("failed to perform idp authentication")
		}
		if idpAuthStatus.Result.State == "Success" && idpAuthStatus.Result.Token != "" {
			ai.sessionDetails = &identity.AdvanceAuthResult{
				Token:         idpAuthStatus.Result.Token,
				TokenLifetime: idpAuthStatus.Result.TokenLifetime,
				RefreshToken:  idpAuthStatus.Result.RefreshToken,
			}
			ai.session.UpdateToken(idpAuthStatus.Result.Token, "Bearer")
			delta := ai.sessionDetails.TokenLifetime
			if delta == 0 {
				delta = DefaultTokenLifetimeSeconds
			}
			ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(delta) * time.Second))
			if ai.cacheAuthentication {
				if err := ai.saveCache(profile); err != nil {
					return err
				}
			}
			break
		}
		time.Sleep(msPollInterval)
	}
	return nil
}

func (ai *IdsecIdentity) pickMechanism(challenge *identity.Challenge) (*identity.Mechanism, error) {
	var supportedMechanisms []*identity.Mechanism
	for _, m := range challenge.Mechanisms {
		for _, sm := range supportedIdentityMechanisms {
			if strings.ToLower(m.Name) == sm {
				supportedMechanisms = append(supportedMechanisms, &m)
				break
			}
		}
	}
	options := make([]string, len(supportedMechanisms))
	for i, m := range supportedMechanisms {
		options[i] = factors[strings.ToLower(m.Name)]
	}

	prompt := &survey.Select{
		Message: "Please pick one of the following MFA methods",
		Options: options,
	}
	if ai.mfaType != "" {
		mfaTypeFactor := factors[strings.ToLower(ai.mfaType)]
		for _, option := range options {
			if option == mfaTypeFactor {
				prompt.Default = option
				break
			}
		}
	}

	var selectedOption string
	err := survey.AskOne(prompt, &selectedOption)
	if err != nil {
		return nil, err
	}
	for name, value := range factors {
		if value == selectedOption {
			selectedOption = name
			break
		}
	}
	ai.mfaType = selectedOption
	for _, m := range supportedMechanisms {
		if strings.ToLower(m.Name) == ai.mfaType {
			return m, nil
		}
	}
	return nil, errors.New("selected MFA method not found in supported mechanisms")
}

func (ai *IdsecIdentity) inputRoutine(chanWrite chan string, chanRead chan string, mechanism *identity.Mechanism, oobAdvanceResp *identity.AdvanceAuthMidResponse) {
	currentTry := 0
	for {
		if currentTry == mechanismRetryCount {
			chanWrite <- "ERROR"
			return
		}
		var answer string
		if oobAdvanceResp.Result.GeneratedAuthValue != "" {
			prompt := &survey.Password{
				Message: fmt.Sprintf("Sent Mobile Authenticator request to your device with a value of [%s]. Please follow the instructions to proceed with authentication or enter verification code here.", oobAdvanceResp.Result.GeneratedAuthValue),
			}
			err := survey.AskOne(prompt, &answer)
			if err != nil {
				chanWrite <- "ERROR"
				return
			}
		} else {
			prompt := &survey.Password{
				Message: mechanism.PromptMechChosen,
			}
			err := survey.AskOne(prompt, &answer)
			if err != nil {
				chanWrite <- "ERROR"
				return
			}
		}
		if answer == "" {
			chanWrite <- "ERROR"
			return
		}
		chanWrite <- answer
		time.Sleep(recvRoutineInterval)
		select {
		case response := <-chanRead:
			if response == "CONTINUE" {
				currentTry++
				continue
			}
			return
		default:
			continue
		}
	}
}

func (ai *IdsecIdentity) startInputRoutine(pipeWrite chan string, pipeRead chan string, mechanism *identity.Mechanism, oobAdvanceResp *identity.AdvanceAuthMidResponse) error {
	if ai.interactionRoutine != nil {
		return errors.New("interaction thread is already in progress")
	}
	ai.interactionRoutine = make(chan string)
	go ai.inputRoutine(pipeWrite, pipeRead, mechanism, oobAdvanceResp)
	return nil
}

func (ai *IdsecIdentity) stopInputRoutine(flush bool) {
	if ai.interactionRoutine != nil {
		close(ai.interactionRoutine)
		ai.interactionRoutine = nil
	}
}

func (ai *IdsecIdentity) pollAuthentication(profile *models.IdsecProfile, mechanism *identity.Mechanism, startAuthResponse *identity.StartAuthResponse, oobAdvanceResp *identity.AdvanceAuthMidResponse, isInteractive bool) error {
	if ai.isPolling {
		return errors.New("MFA Polling is already in progress")
	}
	ai.isPolling = true
	defer func() { ai.isPolling = false }()

	chanWrite := make(chan string)
	chanRead := make(chan string)

	if isInteractive {
		if err := ai.startInputRoutine(chanWrite, chanRead, mechanism, oobAdvanceResp); err != nil {
			return err
		}
	}

	startTime := time.Now()
	var advanceResp interface{} = nil
	var err error
	var flush = true
	for ai.isPolling {
		if time.Since(startTime) >= secondsPollTime {
			return errors.New("timeout reached while polling for user answer")
		}

		select {
		case mfaCode := <-chanWrite:
			if mfaCode == "ERROR" {
				return errors.New("failed to get answer for MFA factor")
			}
			advanceResp, err = ai.advanceAuthentication(mechanism.MechanismID, startAuthResponse.Result.SessionID, mfaCode, "Answer", false)
			if err != nil {
				return err
			}
			if _, ok := advanceResp.(*identity.AdvanceAuthResponse); ok {
				chanRead <- "DONE"
				flush = false
			} else if midResp, ok := advanceResp.(*identity.AdvanceAuthMidResponse); ok {
				if !midResp.Success {
					flush = false
					ai.isPolling = false
					if isInteractive {
						ai.stopInputRoutine(flush)
					}
					return errors.New("failed to advance authentication")
				}
				if midResp.Result.Summary == "NewPackage" {
					flush = false
					ai.isPolling = false
					if isInteractive {
						ai.stopInputRoutine(flush)
					}
					return nil
				}
			} else {
				chanRead <- "CONTINUE"
			}
		case <-time.After(msPollInterval):
			advanceResp, err = ai.advanceAuthentication(mechanism.MechanismID, startAuthResponse.Result.SessionID, "", "Poll", false)
			if err != nil {
				return err
			}
		}
		if advanceResp != nil {
			if _, ok := advanceResp.(*identity.AdvanceAuthResponse); ok {
				ai.isPolling = false
				if isInteractive {
					ai.stopInputRoutine(flush)
				}
				ai.sessionDetails = &advanceResp.(*identity.AdvanceAuthResponse).Result
				ai.session.UpdateToken(ai.sessionDetails.Token, "Bearer")
				delta := ai.sessionDetails.TokenLifetime
				if delta == 0 {
					delta = DefaultTokenLifetimeSeconds
				}
				ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(delta) * time.Second))
				if ai.cacheAuthentication {
					if err := ai.saveCache(profile); err != nil {
						return err
					}
				}
				return nil
			} else if midResp, ok := advanceResp.(*identity.AdvanceAuthMidResponse); ok {
				if midResp.Result.Summary == "NewPackage" {
					ai.isPolling = false
					if isInteractive {
						ai.stopInputRoutine(flush)
					}
					return nil
				}
			}
		}
	}
	return nil
}

func (ai *IdsecIdentity) performUpAuthentication(
	profile *models.IdsecProfile, mechanism *identity.Mechanism, interactive bool,
	startAuthResponse *identity.StartAuthResponse,
	currentChallengeIdx int) (string, int, error) {
	currentChallengeIdx++
	if ai.password == "" {
		if !interactive {
			return "", -1, errors.New("no password and not interactive, cannot continue")
		}
		var answer string
		prompt := &survey.Password{
			Message: "Identity Security Platform Secret",
		}
		err := survey.AskOne(prompt, &answer)
		if err != nil {
			return "", -1, err
		}
		if answer == "" {
			return "", -1, errors.New("empty response by user")
		}
		ai.password = answer
	}
	advanceResp, err := ai.advanceAuthentication(mechanism.MechanismID, startAuthResponse.Result.SessionID, ai.password, "Answer", false)
	if err != nil {
		return "", -1, err
	}
	if _, ok := advanceResp.(*identity.AdvanceAuthResponse); ok && len(startAuthResponse.Result.Challenges) == 1 {
		ai.sessionDetails = &advanceResp.(*identity.AdvanceAuthResponse).Result
		ai.session.UpdateToken(ai.sessionDetails.Token, "Bearer")
		delta := ai.sessionDetails.TokenLifetime
		if delta == 0 {
			delta = DefaultTokenLifetimeSeconds
		}
		ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(delta) * time.Second))
		if ai.cacheAuthentication {
			if err := ai.saveCache(profile); err != nil {
				return "", -1, err
			}
		}
		return "DONE", currentChallengeIdx, nil
	}
	if midResp, ok := advanceResp.(*identity.AdvanceAuthMidResponse); ok {
		if !midResp.Success {
			return "ERROR", currentChallengeIdx, fmt.Errorf("failed to advance auth [%v]", midResp.Message)
		}
	}
	return "CONTINUE", currentChallengeIdx, nil
}

// GetApps Returns the applications to which the user is logged in.
func (ai *IdsecIdentity) GetApps() (map[string]interface{}, error) {
	if ai.sessionDetails == nil {
		return nil, errors.New("identity authentication is required first")
	}

	// Save the current cookies
	cookies := ai.session.GetCookies()
	response, err := ai.session.Post(
		context.Background(),
		"UPRest/GetUPData",
		nil,
	)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			ai.logger.Warning("Error closing response body")
		}
	}(response.Body)

	// Restore the cookies
	ai.session.SetCookies(cookies)

	// Parse the response
	var result map[string]interface{}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return nil, err
	}

	return result, nil
}

// AuthIdentity Authenticates to Identity with the information specified in the constructor.
// If MFA is configured and `interactive` is enabled, the user is prompted for the MFA secret.
// The auth token and other details are stored in the object for future use.
func (ai *IdsecIdentity) AuthIdentity(profile *models.IdsecProfile, interactive bool, force bool) error {
	ai.logger.Debug("Attempting to authenticate to Identity")
	if ai.cacheAuthentication && !force {
		if ai.loadedFromCache {
			if time.Time(ai.sessionExp).After(time.Now()) {
				ai.logger.Info("Loaded identity details from cache")
				return nil
			}
		} else {
			ai.loadCache(profile)
			if time.Time(ai.sessionExp).After(time.Now()) {
				ai.logger.Info("Loaded identity details from cache")
				return nil
			}
		}
	}
	ai.sessionDetails = nil
	ai.session = common.NewSimpleIdsecClient(ai.session.BaseURL)
	ai.session.SetHeaders(DefaultHeaders())
	var startAuthResponse *identity.StartAuthResponse
	var err error
	cacheKey := fmt.Sprintf("%s_%s", ai.IdentityURL(), ai.username)
	if cachedResponse, exists := lastStartAuthResponses[cacheKey]; exists {
		if time.Since(cachedResponse.timestamp).Seconds() < secondsLastStartAuthRespDelta.Seconds() {
			startAuthResponse = cachedResponse.lastResponse
			ai.session.SetCookies(cachedResponse.cookies)
		}
		delete(lastStartAuthResponses, cacheKey)
	}

	if startAuthResponse == nil {
		startAuthResponse, err = ai.startAuthentication()
		if err != nil {
			return err
		}
	}

	if startAuthResponse.Result.IdpRedirectURL != "" {
		return ai.performIdpAuthentication(startAuthResponse, profile, interactive)
	}

	currentChallengeIdx := 0
	var result string
	if len(startAuthResponse.Result.Challenges[currentChallengeIdx].Mechanisms) > 1 && interactive {
		mechanism, err := ai.pickMechanism(&startAuthResponse.Result.Challenges[currentChallengeIdx])
		if err != nil {
			return err
		}
		if strings.ToLower(mechanism.Name) == "up" {
			result, currentChallengeIdx, err = ai.performUpAuthentication(profile, mechanism, interactive, startAuthResponse, currentChallengeIdx)
			if err != nil {
				return err
			}
			if result == "DONE" {
				return nil
			}
		} else {
			currentChallengeIdx++
			oobAdvanceResp, err := ai.advanceAuthentication(mechanism.MechanismID, startAuthResponse.Result.SessionID, "", "StartOOB", false)
			if err != nil {
				return err
			}
			err = ai.pollAuthentication(profile, mechanism, startAuthResponse, oobAdvanceResp.(*identity.AdvanceAuthMidResponse), interactive)
			if err != nil {
				return err
			}
			if ai.sessionDetails != nil {
				return nil
			}
		}
	} else {
		mechanism := &startAuthResponse.Result.Challenges[currentChallengeIdx].Mechanisms[0]
		if strings.ToLower(mechanism.Name) == "up" {
			result, currentChallengeIdx, err = ai.performUpAuthentication(profile, mechanism, interactive, startAuthResponse, currentChallengeIdx)
			if err != nil {
				return err
			}
			if result == "DONE" {
				return nil
			}
		}
	}
	if interactive {
		if _, err = ai.pickMechanism(&startAuthResponse.Result.Challenges[currentChallengeIdx]); err != nil {
			return err
		}
	}

	if ai.mfaType != "" && currentChallengeIdx == 1 {
		for _, mechanism := range startAuthResponse.Result.Challenges[currentChallengeIdx].Mechanisms {
			if strings.ToLower(mechanism.Name) == ai.mfaType {
				oobAdvanceResp, err := ai.advanceAuthentication(mechanism.MechanismID, startAuthResponse.Result.SessionID, "", "StartOOB", false)
				if err != nil {
					return err
				}
				return ai.pollAuthentication(profile, &mechanism, startAuthResponse, oobAdvanceResp.(*identity.AdvanceAuthMidResponse), interactive)
			}
		}
	}

	if !interactive {
		return errors.New("user interaction is not supported while not interactive and mfa type given was not found")
	}

	for _, challenge := range startAuthResponse.Result.Challenges[currentChallengeIdx:] {
		mechanism, err := ai.pickMechanism(&challenge)
		if err != nil {
			return err
		}
		oobAdvanceResp, err := ai.advanceAuthentication(mechanism.MechanismID, startAuthResponse.Result.SessionID, "", "StartOOB", false)
		if err != nil {
			return err
		}
		if err := ai.pollAuthentication(profile, mechanism, startAuthResponse, oobAdvanceResp.(*identity.AdvanceAuthMidResponse), interactive); err != nil {
			return err
		}
	}
	return nil
}

// RefreshAuthIdentity Performs a token refresh with the object's existing details.
func (ai *IdsecIdentity) RefreshAuthIdentity(profile *models.IdsecProfile, interactive bool, force bool) error {
	if ai.sessionDetails == nil || ai.sessionDetails.Token == "" {
		// We only refresh platform token at the moment, call the normal authentication instead
		return ai.AuthIdentity(profile, interactive, force)
	}

	ai.logger.Debug("Attempting to refresh authenticate to Identity")
	var savedCookies map[string]string
	if ai.session != nil {
		savedCookies = ai.session.GetCookies()
	}
	ai.session = common.NewSimpleIdsecClient(ai.session.BaseURL)
	ai.session.SetHeaders(DefaultHeaders())

	// Decode the token to get the tenant ID
	token, _, err := new(jwt.Parser).ParseUnverified(ai.sessionDetails.Token, jwt.MapClaims{})
	if err != nil {
		return err
	}
	claims := token.Claims.(jwt.MapClaims)
	platformTenantID := claims["tenant_id"].(string)

	refreshCookies := map[string]string{
		fmt.Sprintf("refreshToken-%s", platformTenantID): ai.sessionDetails.RefreshToken,
		fmt.Sprintf("idToken-%s", platformTenantID):      ai.sessionDetails.Token,
	}
	ai.session.SetCookies(refreshCookies)
	response, err := ai.session.Post(context.Background(), "OAuth2/RefreshPlatformToken", nil)
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
		return errors.New("failed to refresh token")
	}

	var newToken, newRefreshToken string
	for _, cookie := range response.Cookies() {
		if cookie.Name == fmt.Sprintf("idToken-%s", platformTenantID) {
			newToken = cookie.Value
		}
		if cookie.Name == fmt.Sprintf("refreshToken-%s", platformTenantID) {
			newRefreshToken = cookie.Value
		}
	}

	if newToken == "" || newRefreshToken == "" {
		return errors.New("failed to retrieve refresh tokens cookies")
	}

	if savedCookies != nil {
		ai.session.SetCookies(savedCookies)
	}
	ai.session.UpdateToken(newToken, "Bearer")

	ai.sessionDetails.Token = newToken
	ai.sessionDetails.RefreshToken = newRefreshToken

	// Decode the new token to get the expiration time
	newTokenClaims, _, err := new(jwt.Parser).ParseUnverified(newToken, jwt.MapClaims{})
	if err != nil {
		return err
	}
	newClaims := newTokenClaims.Claims.(jwt.MapClaims)
	exp := int64(newClaims["exp"].(float64))
	iat := int64(newClaims["iat"].(float64))
	ai.sessionDetails.TokenLifetime = int(exp - iat)

	delta := ai.sessionDetails.TokenLifetime
	if delta == 0 {
		delta = DefaultTokenLifetimeSeconds
	}
	ai.sessionExp = commonmodels.IdsecRFC3339Time(time.Now().Add(time.Duration(delta) * time.Second))

	if ai.cacheAuthentication {
		if err := ai.saveCache(profile); err != nil {
			return err
		}
	}

	return nil
}

// Session returns the current identity session
func (ai *IdsecIdentity) Session() *common.IdsecClient {
	return ai.session
}

// SessionToken returns the current identity session token if logged in
func (ai *IdsecIdentity) SessionToken() string {
	if ai.sessionDetails != nil {
		if ai.sessionDetails.Token != "" {
			return ai.sessionDetails.Token
		}
		if ai.sessionDetails.Auth != "" {
			return ai.sessionDetails.Auth
		}
	}
	return ""
}

// SessionDetails returns the current identity session details if logged in
func (ai *IdsecIdentity) SessionDetails() *identity.AdvanceAuthResult {
	return ai.sessionDetails
}

// IdentityURL returns the current identity URL
func (ai *IdsecIdentity) IdentityURL() string {
	return ai.session.BaseURL
}
