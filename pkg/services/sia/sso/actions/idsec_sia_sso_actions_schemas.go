package actions

import ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"

// ActionToSchemaMap is a map that defines the mapping between SSO action names and their corresponding schema types.
var ActionToSchemaMap = map[string]interface{}{
	"short-lived-password":           &ssomodels.IdsecSIASSOGetShortLivedPassword{},
	"short-lived-client-certificate": &ssomodels.IdsecSIASSOGetShortLivedClientCertificate{},
	"short-lived-oracle-wallet":      &ssomodels.IdsecSIASSOGetShortLivedOracleWallet{},
	"short-lived-rdp-file":           &ssomodels.IdsecSIASSOGetShortLivedRDPFile{},
	"short-lived-token-info":         &ssomodels.IdsecSIASSOGetTokenInfo{},
	"short-lived-ssh-key":            &ssomodels.IdsecSIASSOGetSSHKey{},
}
