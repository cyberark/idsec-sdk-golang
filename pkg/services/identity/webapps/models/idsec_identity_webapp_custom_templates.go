package models

// IdsecIdentityWebappCustomTemplates represents a list of custom webapp templates as returned by the Identity API.
type IdsecIdentityWebappCustomTemplates struct {
	Templates []*IdsecIdentityWebappTemplate `json:"templates" mapstructure:"templates" flag:"templates" desc:"List of custom webapp templates"`
}
