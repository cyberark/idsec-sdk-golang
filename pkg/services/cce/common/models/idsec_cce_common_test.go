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

// TestIdsecCCEPropertyValue_UnmarshalJSON_Bool ensures IdsecCCEPropertyValue - a bool/string
// union type - can be decoded directly by encoding/json when a property value is a boolean
// (e.g. GCP's TfProject/TfOrganization decode the full API response with json.NewDecoder
// rather than mapstructure.Decode). Before UnmarshalJSON was implemented, this failed with
// "cannot unmarshal bool into Go struct field ... IdsecCCEPropertyValue".
func TestIdsecCCEPropertyValue_UnmarshalJSON_Bool(t *testing.T) {
	rawJSON := `{
		"name": "dpa",
		"status": "Completely added",
		"errors": [],
		"properties": [
			{"name": "cce_broken_role", "value": false}
		]
	}`

	var service IdsecCCEOnboardedService
	require.NoError(t, json.Unmarshal([]byte(rawJSON), &service))

	require.NotNil(t, service.Properties)
	props := *service.Properties
	require.Len(t, props, 1)
	require.Equal(t, "cce_broken_role", props[0].Name)
	require.NotNil(t, props[0].Value.BoolValue)
	require.False(t, *props[0].Value.BoolValue)
	require.Nil(t, props[0].Value.StringValue)
}

// TestIdsecCCEPropertyValue_UnmarshalJSON_String covers the string-valued case for the same
// direct encoding/json decode path.
func TestIdsecCCEPropertyValue_UnmarshalJSON_String(t *testing.T) {
	rawJSON := `{"name": "azure_domain", "value": "example.com"}`

	var prop IdsecCCEPropertyOutput
	require.NoError(t, json.Unmarshal([]byte(rawJSON), &prop))

	require.NotNil(t, prop.Value.StringValue)
	require.Equal(t, "example.com", *prop.Value.StringValue)
	require.Nil(t, prop.Value.BoolValue)
}

// TestIdsecCCEPropertyValue_MarshalJSON ensures MarshalJSON emits the raw bool/string value
// rather than the BoolValue/StringValue struct fields.
func TestIdsecCCEPropertyValue_MarshalJSON(t *testing.T) {
	boolVal := true
	prop := IdsecCCEPropertyOutput{Name: "cce_broken_role", Value: IdsecCCEPropertyValue{BoolValue: &boolVal}}

	data, err := json.Marshal(prop)
	require.NoError(t, err)
	require.JSONEq(t, `{"name":"cce_broken_role","value":true}`, string(data))
}
