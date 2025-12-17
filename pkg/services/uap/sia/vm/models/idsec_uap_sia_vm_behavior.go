package models

import (
	"errors"
)

// IdsecUAPSSIAVMSSHProfile defines the SSH profile for this virtual machine access policy.
type IdsecUAPSSIAVMSSHProfile struct {
	Username string `json:"username" mapstructure:"username" flag:"username" desc:"Username which the user will connect with on the certificate"`
}

// Serialize converts the SSH profile to a map.
func (s *IdsecUAPSSIAVMSSHProfile) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"username": s.Username,
	}
}

// Deserialize populates the SSH profile from a map.
func (s *IdsecUAPSSIAVMSSHProfile) Deserialize(data map[string]interface{}) error {
	if username, ok := data["username"].(string); ok {
		s.Username = username
	} else {
		return errors.New("username must be a string")
	}
	return nil
}

// IdsecUAPSSIAVMEphemeralUser defines the ephemeral user method related data for this virtual machine access policy.
type IdsecUAPSSIAVMEphemeralUser struct {
	AssignGroups                 []string `json:"assign_groups" mapstructure:"assign_groups" flag:"assign-groups" desc:"Predefined assigned local groups of the user"`
	EnableEphemeralUserReconnect bool     `json:"enable_ephemeral_user_reconnect" mapstructure:"enable_ephemeral_user_reconnect" flag:"enable-ephemeral-user-reconnect" desc:"Whether the ephemeral user can reconnect"`
}

// Serialize converts the ephemeral user to a map.
func (s *IdsecUAPSSIAVMEphemeralUser) Serialize() map[string]interface{} {
	return map[string]interface{}{
		"assignGroups":                 s.AssignGroups,
		"enableEphemeralUserReconnect": s.EnableEphemeralUserReconnect,
	}
}

// Deserialize populates the ephemeral user from a map.
func (s *IdsecUAPSSIAVMEphemeralUser) Deserialize(data map[string]interface{}) error {
	if assignGroups, ok := data["assign_groups"].([]interface{}); ok {
		for _, group := range assignGroups {
			if groupStr, ok := group.(string); ok {
				s.AssignGroups = append(s.AssignGroups, groupStr)
			} else {
				return errors.New("assign_groups must be an array of strings")
			}
		}
	} else {
		return errors.New("assignGroups must be an array of strings")
	}

	if reconnect, ok := data["enable_ephemeral_user_reconnect"].(bool); ok {
		s.EnableEphemeralUserReconnect = reconnect
	} else {
		return errors.New("enable_ephemeral_user_reconnect must be a boolean")
	}
	return nil
}

// IdsecUAPSSIAVMDomainEphemeralUser defines the domain ephemeral user method related data for this virtual machine access policy.
type IdsecUAPSSIAVMDomainEphemeralUser struct {
	IdsecUAPSSIAVMEphemeralUser `mapstructure:",squash"`
	AssignDomainGroups          []string `json:"assign_domain_groups" mapstructure:"assign_domain_groups" flag:"assign-domain-groups" desc:"Predefined assigned domain groups of the user"`
}

// Serialize converts the domain ephemeral user to a map.
func (s *IdsecUAPSSIAVMDomainEphemeralUser) Serialize() map[string]interface{} {
	data := s.IdsecUAPSSIAVMEphemeralUser.Serialize()
	data["assignDomainGroups"] = s.AssignDomainGroups
	return data
}

// Deserialize populates the domain ephemeral user from a map.
func (s *IdsecUAPSSIAVMDomainEphemeralUser) Deserialize(data map[string]interface{}) error {
	if err := s.IdsecUAPSSIAVMEphemeralUser.Deserialize(data); err != nil {
		return err
	}

	if assignDomainGroups, ok := data["assign_domain_groups"].([]interface{}); ok {
		for _, group := range assignDomainGroups {
			if groupStr, ok := group.(string); ok {
				s.AssignDomainGroups = append(s.AssignDomainGroups, groupStr)
			} else {
				return errors.New("assign_domain_groups must be an array of strings")
			}
		}
	} else {
		return errors.New("assign_domain_groups must be an array of strings")
	}
	return nil
}

// IdsecUAPSSIAVMRDPProfile defines the RDP profile for this virtual machine access policy.
type IdsecUAPSSIAVMRDPProfile struct {
	LocalEphemeralUser  *IdsecUAPSSIAVMEphemeralUser       `json:"local_ephemeral_user,omitempty" mapstructure:"local_ephemeral_user" flag:"local-ephemeral-user" desc:"Local ephemeral user method related data"`
	DomainEphemeralUser *IdsecUAPSSIAVMDomainEphemeralUser `json:"domain_ephemeral_user,omitempty" mapstructure:"domain_ephemeral_user" flag:"domain-ephemeral-user" desc:"Domain ephemeral user method related data"`
}

// Serialize converts the RDP profile to a map.
func (p *IdsecUAPSSIAVMRDPProfile) Serialize() map[string]interface{} {
	data := make(map[string]interface{})
	if p.LocalEphemeralUser != nil && len(p.LocalEphemeralUser.AssignGroups) > 0 {
		data["localEphemeralUser"] = p.LocalEphemeralUser.Serialize()
	}
	if p.DomainEphemeralUser != nil && (len(p.DomainEphemeralUser.AssignGroups) > 0 || len(p.DomainEphemeralUser.AssignDomainGroups) > 0) {
		data["domainEphemeralUser"] = p.DomainEphemeralUser.Serialize()
	}
	return data
}

// Deserialize populates the RDP profile from a map.
func (p *IdsecUAPSSIAVMRDPProfile) Deserialize(data map[string]interface{}) error {
	if localUser, ok := data["local_ephemeral_user"].(map[string]interface{}); ok {
		p.LocalEphemeralUser = &IdsecUAPSSIAVMEphemeralUser{}
		if err := p.LocalEphemeralUser.Deserialize(localUser); err != nil {
			return err
		}
	}

	if domainUser, ok := data["domain_ephemeral_user"].(map[string]interface{}); ok {
		p.DomainEphemeralUser = &IdsecUAPSSIAVMDomainEphemeralUser{}
		if err := p.DomainEphemeralUser.Deserialize(domainUser); err != nil {
			return err
		}
	}
	return nil
}

// IdsecUAPSSIAVMBehavior defines the behavior of a virtual machine access policy, including SSH and RDP profiles.
type IdsecUAPSSIAVMBehavior struct {
	SSHProfile *IdsecUAPSSIAVMSSHProfile `json:"ssh_profile,omitempty" mapstructure:"ssh_profile" flag:"ssh-profile" desc:"The SSH profile for this virtual machine access policy"`
	RDPProfile *IdsecUAPSSIAVMRDPProfile `json:"rdp_profile,omitempty" mapstructure:"rdp_profile" flag:"rdp-profile" desc:"The RDP profile for this virtual machine access policy"`
}

// Serialize converts the VM behavior to a map.
func (b *IdsecUAPSSIAVMBehavior) Serialize() map[string]interface{} {
	data := map[string]interface{}{
		"connectAs": map[string]interface{}{},
	}
	if b.SSHProfile != nil {
		data["connectAs"].(map[string]interface{})["ssh"] = b.SSHProfile.Serialize()
	}
	if b.RDPProfile != nil {
		data["connectAs"].(map[string]interface{})["rdp"] = b.RDPProfile.Serialize()
	}
	return data
}

// Deserialize populates the VM behavior from a map.
func (b *IdsecUAPSSIAVMBehavior) Deserialize(data map[string]interface{}) error {
	if _, ok := data["connectAs"]; !ok {
		return errors.New("connectAs field is required")
	}

	if sshProfile, ok := data["connectAs"].(map[string]interface{})["ssh"]; ok {
		b.SSHProfile = &IdsecUAPSSIAVMSSHProfile{}
		if err := b.SSHProfile.Deserialize(sshProfile.(map[string]interface{})); err != nil {
			return err
		}
	}

	if rdpProfile, ok := data["connectAs"].(map[string]interface{})["rdp"]; ok {
		b.RDPProfile = &IdsecUAPSSIAVMRDPProfile{}
		if err := b.RDPProfile.Deserialize(rdpProfile.(map[string]interface{})); err != nil {
			return err
		}
	}

	return nil
}
