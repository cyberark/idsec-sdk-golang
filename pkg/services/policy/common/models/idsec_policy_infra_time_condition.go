package models

// IdsecPolicyInfraTimeCondition represents a 4-digit "HH:MM" access-window for VM/DB policies.
// This is distinct from IdsecPolicyTimeCondition (6-digit "HH:MM:SS") used by other policy types (DPA-16264).
type IdsecPolicyInfraTimeCondition struct {
	DaysOfTheWeek []int  `json:"days_of_the_week" mapstructure:"days_of_the_week" flag:"days-of-the-week" desc:"The days of the week to include in the policy's access window, where Sunday=0, Monday=1,..., Saturday=6, comma-separated" validate:"dive,min=0,max=6" default:"0,1,2,3,4,5,6"`
	FromHour      string `json:"from_hour,omitempty" mapstructure:"from_hour,omitempty" flag:"from-hour" desc:"The start time of the policy's access window, in 4-digit HH:MM format" validate:"regexp=^\\d{2}:\\d{2}$" default:""`
	ToHour        string `json:"to_hour,omitempty" mapstructure:"to_hour,omitempty" flag:"to-hour" desc:"The end time of the policy's access window, in 4-digit HH:MM format" validate:"regexp=^\\d{2}:\\d{2}$" default:""`
}
