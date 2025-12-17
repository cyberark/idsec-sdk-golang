package auth

import (
	"encoding/json"
	"fmt"
)

// IdsecAuthProfile represents the authentication profile for Idsec SIA.
type IdsecAuthProfile struct {
	Username           string                  `json:"username" mapstructure:"username" flag:"username" desc:"Username"`
	AuthMethod         IdsecAuthMethod         `json:"auth_method" mapstructure:"auth_method" flag:"-"`
	AuthMethodSettings IdsecAuthMethodSettings `json:"auth_method_settings" mapstructure:"auth_method_settings" flag:"-"`
}

// UnmarshalJSON unmarshals the JSON data into the IdsecAuthProfile struct.
func (a *IdsecAuthProfile) UnmarshalJSON(data []byte) error {
	type Alias IdsecAuthProfile
	aux := &struct {
		AuthMethodSettings json.RawMessage `json:"auth_method_settings"`
		*Alias
	}{
		Alias: (*Alias)(a),
	}

	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}

	var settings IdsecAuthMethodSettings
	switch a.AuthMethod {
	case Identity:
		settings = &IdentityIdsecAuthMethodSettings{}
	case IdentityServiceUser:
		settings = &IdentityServiceUserIdsecAuthMethodSettings{}
	case Direct:
		settings = &DirectIdsecAuthMethodSettings{}
	case Default:
		settings = &DefaultIdsecAuthMethodSettings{}
	default:
		return fmt.Errorf("unknown auth method: %s", a.AuthMethod)
	}

	if err := json.Unmarshal(aux.AuthMethodSettings, settings); err != nil {
		return err
	}

	a.AuthMethodSettings = settings
	return nil
}
