package models

// IdsecARSListAccessRequestForms is the input for listing access request forms.
type IdsecARSListAccessRequestForms struct {
	TargetCategory string `json:"target_category" mapstructure:"target_category" flag:"target-category" desc:"Target category to list the access request forms for" choices:"CLOUD_CONSOLE,VM,GROUP" validate:"required,oneof=CLOUD_CONSOLE VM GROUP"`
	RequestType    string `json:"request_type,omitempty" mapstructure:"request_type,omitempty" flag:"request-type" desc:"Request type to list the access request forms for" default:"ON_DEMAND" choices:"DUAL_CONTROL,ON_DEMAND" validate:"omitempty,oneof=DUAL_CONTROL ON_DEMAND"`
}
