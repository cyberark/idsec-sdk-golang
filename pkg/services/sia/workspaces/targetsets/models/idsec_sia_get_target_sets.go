package models

// IdsecSIAGetTargetSets defines the request to retrieve multiple target sets by names.
//
// This model supports batch retrieval of target sets, which is more efficient
// than making individual GET calls for each target set.
//
// Parameters:
//   - id_list: Array of target set ids to retrieve
//
// Example:
//
//	request := &models.IdsecSIAGetTargetSets{
//	    IDList: []string{
//	        "prod-domain.com",
//	        "staging-domain.com",
//	        "192.168.1.0/24",
//	    },
//	}
//	response, err := service.GetTargetSets(request)
type IdsecSIAGetTargetSets struct {
	// IDList is the array of target set ids to retrieve.
	IDList []string `json:"id_list" mapstructure:"id_list" flag:"id_list" desc:"The IDs of target sets to retrieve." validate:"required"`
}
