package models

import (
	"encoding/json"
	"testing"

	"github.com/mitchellh/mapstructure"
	"github.com/stretchr/testify/require"
)

// TestIdsecCCEServiceInput_SerializesVersion ensures the per-service version is
// included in the JSON request body sent to the CCE onboarding API.
func TestIdsecCCEServiceInput_SerializesVersion(t *testing.T) {
	input := IdsecCCEServiceInput{
		ServiceName: DPA,
		Version:     "0.0.2",
		Resources: map[string]interface{}{
			"appId": "app-123",
		},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &payload))

	require.Equal(t, "dpa", payload["serviceName"])
	require.Equal(t, "0.0.2", payload["version"], "service version must be included in the serialized request payload")
}

// TestIdsecCCEServiceInput_OmitsEmptyVersion ensures the version key is omitted
// when no version is provided, preserving backward-compatible payloads.
func TestIdsecCCEServiceInput_OmitsEmptyVersion(t *testing.T) {
	input := IdsecCCEServiceInput{
		ServiceName: SCA,
		Resources:   map[string]interface{}{},
	}

	data, err := json.Marshal(input)
	require.NoError(t, err)

	var payload map[string]interface{}
	require.NoError(t, json.Unmarshal(data, &payload))

	_, hasVersion := payload["version"]
	require.False(t, hasVersion, "version should be omitted from the payload when empty")
}

// TestIdsecCCEServiceInput_DecodesVersionFromConfig ensures the version provided
// in Terraform config (decoded via mapstructure) flows into the request model.
func TestIdsecCCEServiceInput_DecodesVersionFromConfig(t *testing.T) {
	config := map[string]interface{}{
		"service_name": "dpa",
		"version":      "0.0.2",
		"resources": map[string]interface{}{
			"appId": "app-123",
		},
	}

	var decoded IdsecCCEServiceInput
	require.NoError(t, mapstructure.Decode(config, &decoded))

	require.Equal(t, "dpa", decoded.ServiceName)
	require.Equal(t, "0.0.2", decoded.Version)

	// Ensure the value round-trips back into the serialized request body.
	data, err := json.Marshal(decoded)
	require.NoError(t, err)
	require.Contains(t, string(data), `"version":"0.0.2"`)
}
