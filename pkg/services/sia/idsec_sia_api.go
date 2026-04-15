package sia

import (
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/access"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/certificates"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/db"
	dbstrongaccounts "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/dbstrongaccounts"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/k8s"
	dbsecrets "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsdb"
	vmsecrets "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/secretsvm"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/settings"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sshca"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	workspacesdb "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacesdb"
	targetsets "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspacestargetsets"
)

// IdsecSIAAPI is a struct that provides access to the Idsec SIA API as a wrapped set of services.
type IdsecSIAAPI struct {
	ssoService              *sso.IdsecSIASSOService
	k8sService              *k8s.IdsecSIAK8SService
	targetSetsService       *targetsets.IdsecSIAWorkspacesTargetSetsService
	workspacesDBService     *workspacesdb.IdsecSIAWorkspacesDBService
	vmSecretsService        *vmsecrets.IdsecSIASecretsVMService
	dbSecretsService        *dbsecrets.IdsecSIASecretsDBService
	dbStrongAccountsService *dbstrongaccounts.IdsecSIADBStrongAccountsService
	accessService           *access.IdsecSIAAccessService
	sshCaService            *sshca.IdsecSIASSHCAService
	dbService               *db.IdsecSIADBService
	settingsService         *settings.IdsecSIASettingsService
	certificatesService     *certificates.IdsecSIACertificatesService
}

// NewIdsecSIAAPI creates a new instance of IdsecSIAAPI with the provided IdsecISPAuth.
func NewIdsecSIAAPI(ispAuth *auth.IdsecISPAuth) (*IdsecSIAAPI, error) {
	var baseIspAuth auth.IdsecAuth = ispAuth

	// Create a shared ISP base service for services that accept it directly
	// This allows sharing the ISP client and telemetry context
	ispBaseService, err := services.NewIdsecISPBaseService(ispAuth, "dpa", ".", "", func(client *common.IdsecClient) error {
		return isp.RefreshClient(client, ispAuth)
	})
	if err != nil {
		return nil, err
	}

	ssoService, err := sso.NewIdsecSIASSOService(ispBaseService)
	if err != nil {
		return nil, err
	}
	k8sService, err := k8s.NewIdsecSIAK8SService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	targetSetsService, err := targetsets.NewIdsecSIAWorkspacesTargetSetsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	workspaceDBService, err := workspacesdb.NewIdsecSIAWorkspacesDBService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	vmSecretsService, err := vmsecrets.NewIdsecSIASecretsVMService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	dbSecretsService, err := dbsecrets.NewIdsecSIASecretsDBService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	dbStrongAccountsService, err := dbstrongaccounts.NewIdsecSIADBStrongAccountsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	accessService, err := access.NewIdsecSIAAccessService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	sshCaService, err := sshca.NewIdsecSIASSHCAService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	dbService, err := db.NewIdsecSIADBService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	settingsService, err := settings.NewIdsecSIASettingsService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	certificatesService, err := certificates.NewIdsecSIACertificatesService(baseIspAuth)
	if err != nil {
		return nil, err
	}
	return &IdsecSIAAPI{
		ssoService:              ssoService,
		k8sService:              k8sService,
		targetSetsService:       targetSetsService,
		workspacesDBService:     workspaceDBService,
		vmSecretsService:        vmSecretsService,
		dbSecretsService:        dbSecretsService,
		dbStrongAccountsService: dbStrongAccountsService,
		accessService:           accessService,
		sshCaService:            sshCaService,
		dbService:               dbService,
		settingsService:         settingsService,
		certificatesService:     certificatesService,
	}, nil
}

// Sso returns the SSO service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) Sso() *sso.IdsecSIASSOService {
	return api.ssoService
}

// K8s returns the K8S service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) K8s() *k8s.IdsecSIAK8SService {
	return api.k8sService
}

// WorkspacesTargetSets returns the TargetSets service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) WorkspacesTargetSets() *targetsets.IdsecSIAWorkspacesTargetSetsService {
	return api.targetSetsService
}

// WorkspacesDB returns the workspace DB service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) WorkspacesDB() *workspacesdb.IdsecSIAWorkspacesDBService {
	return api.workspacesDBService
}

// SecretsVM returns the VM Secrets service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) SecretsVM() *vmsecrets.IdsecSIASecretsVMService {
	return api.vmSecretsService
}

// SecretsDB returns the DB Secrets service of the IdsecSIAAPI instance.
// Deprecated: Use DBStrongAccounts() instead for strong account operations.
func (api *IdsecSIAAPI) SecretsDB() *dbsecrets.IdsecSIASecretsDBService {
	return api.dbSecretsService
}

// DBStrongAccounts returns the DB Strong Accounts service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) DBStrongAccounts() *dbstrongaccounts.IdsecSIADBStrongAccountsService {
	return api.dbStrongAccountsService
}

// Access returns the access service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) Access() *access.IdsecSIAAccessService {
	return api.accessService
}

// SSHCa returns the ssh-ca service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) SSHCa() *sshca.IdsecSIASSHCAService {
	return api.sshCaService
}

// Db returns the DB service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) Db() *db.IdsecSIADBService {
	return api.dbService
}

// Settings returns the settings service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) Settings() *settings.IdsecSIASettingsService {
	return api.settingsService
}

// Certificates returns the certificates service of the IdsecSIAAPI instance.
func (api *IdsecSIAAPI) Certificates() *certificates.IdsecSIACertificatesService {
	return api.certificatesService
}
