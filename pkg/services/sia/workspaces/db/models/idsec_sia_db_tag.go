package models

// IdsecSIADBTag represents a tag associated with a database in a workspace.
type IdsecSIADBTag struct {
	Key   string `json:"key" mapstructure:"key" flag:"key" desc:"The key of the tag, for example environment." validate:"required"`
	Value string `json:"value" mapstructure:"value" flag:"value" desc:"The value of the tag, for example production." validate:"required"`
}

// IdsecSIADBTagList represents a list of tags associated with a database in a workspace.
type IdsecSIADBTagList struct {
	Tags  []IdsecSIADBTag `json:"tags" mapstructure:"tags" flag:"tags" desc:"The list of tags."`
	Count int           `json:"count" mapstructure:"count" flag:"count" desc:"The number of listed tags."`
}
