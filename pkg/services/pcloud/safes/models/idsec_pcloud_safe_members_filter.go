package models

// IdsecPCloudSafeMembersFilters represents the details required to filter the members of a safe.
type IdsecPCloudSafeMembersFilters struct {
	SafeID     string `json:"safe_id" mapstructure:"safe_id" desc:"The URL encoding of the Safe where you want to filter members. For special characters, enter the encoding of the special character. For example, enter %20 to represent a space" flag:"safe-id" validate:"required"`
	Search     string `json:"search,omitempty" mapstructure:"search" desc:"Search according to the Safe name. Search is performed according to the REST standard (search='search word')" flag:"search"`
	Sort       string `json:"sort,omitempty" mapstructure:"sort" desc:"Sort according to the memberName property in ascending order (default) or descending order to control the sort direction" flag:"sort"`
	Offset     int    `json:"offset,omitempty" mapstructure:"offset" desc:"Offset of the first member that is returned in the collection of results" flag:"offset"`
	Limit      int    `json:"limit,omitempty" mapstructure:"limit" desc:"The maximum number of members that are returned. When used together with the offset parameter, this value determines the number of Safes to return, starting from the first Safe that is returned" flag:"limit"`
	MemberType string `json:"member_type,omitempty" mapstructure:"member_type" desc:"Filter members according to the type (user or group)" flag:"member-type"`
}
