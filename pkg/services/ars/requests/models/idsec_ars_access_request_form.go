package models

// IdsecARSQueryValueType is the value type of a request form question.
type IdsecARSQueryValueType string

// Request form question value types.
const (
	QueryValueTypeString   IdsecARSQueryValueType = "STRING"
	QueryValueTypeText     IdsecARSQueryValueType = "TEXT"
	QueryValueTypeChoice   IdsecARSQueryValueType = "CHOICE"
	QueryValueTypeDatetime IdsecARSQueryValueType = "DATETIME"
	QueryValueTypeDate     IdsecARSQueryValueType = "DATE"
	QueryValueTypeTime     IdsecARSQueryValueType = "TIME"
	QueryValueTypeTimezone IdsecARSQueryValueType = "TIMEZONE"
	QueryValueTypeInteger  IdsecARSQueryValueType = "INTEGER"
	QueryValueTypeBool     IdsecARSQueryValueType = "BOOL"
	QueryValueTypeList     IdsecARSQueryValueType = "LIST"
	QueryValueTypeAny      IdsecARSQueryValueType = "ANY"
)

// IdsecARSValueValidator is a validator applied to a request form question answer.
type IdsecARSValueValidator struct {
	Name string `json:"name" mapstructure:"name" desc:"Name of the validator"`
}

// IdsecARSSurveyQuestion is a single question in a request form.
type IdsecARSSurveyQuestion struct {
	Key string `json:"key" mapstructure:"key" desc:"Key name / id of the question"`
	// Required is either a bool, or a conditional object of the form
	// {"operator": "AND"|"OR", "conditions": [{"name": ..., "key": ..., "condition": <regex>}]}.
	Required     interface{}              `json:"required" mapstructure:"required" desc:"Whether this is a required question, either a bool or a conditional object"`
	Default      interface{}              `json:"default,omitempty" mapstructure:"default,omitempty" desc:"Default value for the question"`
	Title        string                   `json:"title,omitempty" mapstructure:"title,omitempty" desc:"Title of the question"`
	Description  string                   `json:"description,omitempty" mapstructure:"description,omitempty" desc:"Description of the question"`
	ValueType    IdsecARSQueryValueType   `json:"value_type,omitempty" mapstructure:"value_type,omitempty" desc:"Type of the response value"`
	ValueChoices []interface{}            `json:"value_choices,omitempty" mapstructure:"value_choices,omitempty" desc:"If the value is a choice, what are the possible choices"`
	Validators   []IdsecARSValueValidator `json:"validators,omitempty" mapstructure:"validators,omitempty" desc:"Validators for the question"`
}

// IdsecARSSurvey is the structure of a request form.
type IdsecARSSurvey struct {
	Questions []IdsecARSSurveyQuestion `json:"questions" mapstructure:"questions" desc:"Questions required answering on the survey"`
}

// IdsecARSAccessRequestForm is the request form for a target category and request type.
type IdsecARSAccessRequestForm struct {
	TargetCategory string         `json:"target_category" mapstructure:"target_category" desc:"Target category the request form is related to"`
	RequestType    string         `json:"request_type" mapstructure:"request_type" desc:"Request type the request form is related to"`
	RequestForm    IdsecARSSurvey `json:"request_form" mapstructure:"request_form" desc:"Structure of the request form, as the questions to answer when submitting a request"`
}

// IdsecARSAccessRequestForms is the list of request forms matching the given filters.
type IdsecARSAccessRequestForms struct {
	RequestForms []IdsecARSAccessRequestForm `json:"request_forms" mapstructure:"request_forms" desc:"Request forms matching the given filters"`
}
