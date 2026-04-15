// Copyright (c) CyberArk.
// SPDX-License-Identifier: Apache-2.0

package featureadoption

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"net/http"
	"os"
	"strings"
	"time"

	api "github.com/cyberark/idsec-sdk-golang/pkg"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/config"
	authmodels "github.com/cyberark/idsec-sdk-golang/pkg/models/auth"
)

const (
	// FASPath is the API path for feature adoption reporting.
	FASPath = "/api/feature-adoption"
	// DefaultTimeout is the default HTTP client timeout for FAS requests.
	DefaultTimeout = 5 * time.Second
	// TriggeredByBE indicates the event was triggered by a backend service.
	TriggeredByBE = "BE"
)

// ReportOpts holds optional parameters for the FAS report.
type ReportOpts struct {
	// CustomData is optional additional JSON-serializable data.
	CustomData map[string]interface{}
}

// authISPOrPVWA returns the first available authenticator (isp or pvwa) from the API.
// Returns nil if the API is nil or neither authenticator is configured.
func authISPOrPVWA(idsecAPI *api.IdsecAPI) auth.IdsecAuth {
	if idsecAPI == nil {
		return nil
	}
	if a, err := idsecAPI.Authenticator("isp"); err == nil {
		return a
	}
	if a, err := idsecAPI.Authenticator("pvwa"); err == nil {
		return a
	}
	return nil
}

// ReportWithAPI sends a feature adoption report to FAS using the token resolved from IdsecAPI.
// It resolves the authenticator (isp or pvwa) internally, loads the token, and only reports if the token is JWT.
// Skips if FAS URL is unset, telemetry is disabled, no auth configured, or token is not JWT.
// Returns (message, nil) on success or skip; returns ("", err) on failure.
func ReportWithAPI(ctx context.Context, idsecAPI *api.IdsecAPI, metricKey string, tags map[string]string, opts *ReportOpts) (message string, err error) {
	auth := authISPOrPVWA(idsecAPI)
	if auth == nil {
		return "FAS report skipped: no auth configured", nil
	}
	token, loadErr := auth.LoadAuthentication(nil, false)
	if loadErr != nil {
		return "", loadErr
	}
	if token == nil || token.Token == "" {
		return "FAS report skipped: no token or auth error", nil
	}
	if token.TokenType != authmodels.JWT {
		return "FAS report skipped: token is not JWT (PVWA auth not supported for FAS)", nil
	}
	return report(ctx, token.Token, metricKey, tags, opts)
}

// featureAdoptionRequest matches the FeatureAdoptionAuthenticatedDto schema.
type featureAdoptionRequest struct {
	MetricKey      string                 `json:"metric_key"`
	EventTime      int64                  `json:"event_time,omitempty"`
	NumberOfEvents int                    `json:"number_of_events,omitempty"`
	TriggeredBy    string                 `json:"triggered_by,omitempty"`
	Tags           map[string]string      `json:"tags,omitempty"`
	CustomData     map[string]interface{} `json:"custom_data,omitempty"`
}

// Report sends a feature adoption metric to the FAS API.
// It performs a POST to {baseURL}/api/feature-adoption with the given metricKey and tags.
// The token is sent as Authorization: Bearer <token>.
// Returns (message, nil) on success or skip; returns (err.Error(), err) on failure.
func report(ctx context.Context, token, metricKey string, tags map[string]string, opts *ReportOpts) (message string, err error) {
	if os.Getenv(config.IdsecDisableTelemetryCollectionEnvVar) != "" {
		return "FAS report skipped: telemetry disabled", nil
	}
	if metricKey == "" {
		return "", fmt.Errorf("metricKey is required")
	}
	baseURL := getBaseURL()
	if baseURL == "" {
		return "FAS report skipped: no FAS URL (DEPLOY_ENV not prod/integration)", nil
	}

	base := strings.TrimSuffix(baseURL, "/")
	endpoint := fmt.Sprintf("%s%s", base, FASPath)

	eventTime := int64(0)
	numEvents := 1
	triggeredBy := TriggeredByBE
	var customData map[string]interface{}

	metrics := collectTelemetryMetrics()

	if opts != nil {
		customData = opts.CustomData
	}
	finalTags := metricsToTags(metrics)
	if tags != nil {
		maps.Copy(finalTags, tags)
	}

	reqBody := featureAdoptionRequest{
		MetricKey:      metricKey,
		EventTime:      eventTime,
		NumberOfEvents: numEvents,
		TriggeredBy:    triggeredBy,
		Tags:           finalTags,
		CustomData:     customData,
	}

	body, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	if token != "" {
		httpReq.Header.Set("Authorization", "Bearer "+token)
	}

	client := &http.Client{Timeout: DefaultTimeout}
	resp, err := client.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("request failed: %w", err)
	}
	defer func() {
		_ = resp.Body.Close()
	}()

	if resp.StatusCode != http.StatusAccepted {
		return "", fmt.Errorf("FAS returned status %d", resp.StatusCode)
	}

	return "FAS report sent successfully", nil
}
