package models

// Directions in which to sort a list response.
const (
	SortDirectionAsc  = "asc"
	SortDirectionDesc = "desc"
)

// IdsecARSSortQuery describes a single sort clause.
type IdsecARSSortQuery struct {
	Field     string `json:"field,omitempty" mapstructure:"field,omitempty" flag:"field" desc:"Which field to sort the response on"`
	Direction string `json:"direction,omitempty" mapstructure:"direction,omitempty" flag:"direction" desc:"Direction in which to sort the response" choices:"asc,desc" validate:"omitempty,oneof=asc desc"`
}

// IdsecARSFilter filters, sorts and paginates the access requests list.
type IdsecARSFilter struct {
	Filter   string              `json:"filter,omitempty" mapstructure:"filter,omitempty" flag:"filter" desc:"Filter string to perform on the response items"`
	Extended bool                `json:"extended,omitempty" mapstructure:"extended,omitempty" flag:"extended" desc:"Whether to return an extended response or not"`
	Offset   int                 `json:"offset,omitempty" mapstructure:"offset,omitempty" flag:"offset" desc:"Offset of the items for the response"`
	Limit    int                 `json:"limit,omitempty" mapstructure:"limit,omitempty" flag:"limit" desc:"Limit amount of items per page" default:"1000"`
	Sort     []IdsecARSSortQuery `json:"sort,omitempty" mapstructure:"sort,omitempty" flag:"sort" desc:"How to sort the response"`
}
