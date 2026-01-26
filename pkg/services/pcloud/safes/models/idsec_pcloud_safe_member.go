package models

// Possible safe member types
const (
	User  = "User"
	Group = "Group"
	Role  = "Role"
)

// Possible safe member permission sets
const (
	ConnectOnly     = "connect_only"
	ReadOnly        = "read_only"
	Approver        = "approver"
	AccountsManager = "accounts_manager"
	Full            = "full"
	Custom          = "custom"
)

// IdsecPCloudSafeMemberPermissions represents the permissions of a safe member.
type IdsecPCloudSafeMemberPermissions struct {
	UseAccounts                            bool `json:"use_accounts" mapstructure:"use_accounts" desc:"Use accounts but cannot view secrets" default:"false"`
	RetrieveAccounts                       bool `json:"retrieve_accounts" mapstructure:"retrieve_accounts" desc:"Retrieve and view accounts in the Safe" default:"false"`
	ListAccounts                           bool `json:"list_accounts" mapstructure:"list_accounts" desc:"View the Safe's accounts list" default:"false"`
	AddAccounts                            bool `json:"add_accounts" mapstructure:"add_accounts" desc:"Add accounts in the Safe. Users who have this permission automatically have UpdateAccountProperties permissions" default:"false"`
	UpdateAccountContent                   bool `json:"update_account_content" mapstructure:"update_account_content" desc:"Update existing account content" default:"false"`
	UpdateAccountProperties                bool `json:"update_account_properties" mapstructure:"update_account_properties" desc:"Update existing account properties" default:"false"`
	InitiateCPMAccountManagementOperations bool `json:"initiate_cpm_account_management_operations" mapstructure:"initiate_cpm_account_management_operations" desc:"Initiate secrets management operations such as changing, verifying, and reconciling secrets. When set to False, the SpecifyNextAccountContent parameter is also automatically set to False" default:"false"`
	SpecifyNextAccountContent              bool `json:"specify_next_account_content" mapstructure:"specify_next_account_content" desc:"Specify the secret value for the next secrets rotation. can only be specified when the InitiateCPMAccountManagementOperations parameter is set to True. When InitiateCPMAccountManagementOperations is set to False this parameter is automatically set to False" default:"false"`
	RenameAccounts                         bool `json:"rename_accounts" mapstructure:"rename_accounts" desc:"Rename existing accounts in the Safe" default:"false"`
	DeleteAccounts                         bool `json:"delete_accounts" mapstructure:"delete_accounts" desc:"Delete existing secrets in the Safe" default:"false"`
	UnlockAccounts                         bool `json:"unlock_accounts" mapstructure:"unlock_accounts" desc:"Unlock accounts that are locked by other users" default:"false"`
	ManageSafe                             bool `json:"manage_safe" mapstructure:"manage_safe" desc:"Perform administrative tasks in the Safe, including update properties and recover or delete the Safe" default:"false"`
	ManageSafeMembers                      bool `json:"manage_safe_members" mapstructure:"manage_safe_members" desc:"Add and remove Safe members, and update their authorizations in the Safe" default:"false"`
	BackupSafe                             bool `json:"backup_safe" mapstructure:"backup_safe" desc:"Create a backup of a Safe and its contents, and store it in another location" default:"false"`
	ViewAuditLog                           bool `json:"view_audit_log" mapstructure:"view_audit_log" desc:"View account and user activity in the Safe" default:"false"`
	ViewSafeMembers                        bool `json:"view_safe_members" mapstructure:"view_safe_members" desc:"View permissions of Safe members" default:"false"`
	AccessWithoutConfirmation              bool `json:"access_without_confirmation" mapstructure:"access_without_confirmation" desc:"Access the Safe without confirmation from authorized users. This overrides the Safe properties that specify that Safe members require confirmation to access the Safe" default:"false"`
	CreateFolders                          bool `json:"create_folders" mapstructure:"create_folders" desc:"Create folders in the Safe" default:"false"`
	DeleteFolders                          bool `json:"delete_folders" mapstructure:"delete_folders" desc:"Delete folders in the Safe" default:"false"`
	MoveAccountsAndFolders                 bool `json:"move_accounts_and_folders" mapstructure:"move_accounts_and_folders" desc:"Move accounts and folders in the Safe to different folders and subfolders" default:"false"`
	RequestsAuthorizationLevel1            bool `json:"requests_authorization_level_1" mapstructure:"requests_authorization_level_1" desc:"Request authorization level 1 permission" default:"false"`
	RequestsAuthorizationLevel2            bool `json:"requests_authorization_level_2" mapstructure:"requests_authorization_level_2" desc:"Request authorization level 2 permission" default:"false"`
}

// IdsecPCloudSafeMember represents a safe member with its details and permissions.
type IdsecPCloudSafeMember struct {
	SafeID                     string                           `json:"safe_id" mapstructure:"safe_id" desc:"The unique ID of the Safe used when calling Safe APIs"`
	SafeName                   string                           `json:"safe_name" mapstructure:"safe_name" desc:"The unique name of the Safe to which the member belongs"`
	SafeNumber                 int                              `json:"safe_number" mapstructure:"safe_number" desc:"The unique numerical ID of the Safe to which the member belongs"`
	MemberID                   interface{}                      `json:"member_id" mapstructure:"member_id" desc:"The user, group or role ID"`
	MemberName                 string                           `json:"member_name" mapstructure:"member_name" desc:"The Vault user name, Domain user name or group name of the Safe member"`
	MemberType                 string                           `json:"member_type" mapstructure:"member_type" desc:"Type of the member of the safe (User,Group,Role)" choices:"User,Group,Role"`
	MembershipExpirationDate   int                              `json:"membership_expiration_date,omitempty" mapstructure:"membership_expiration_date" desc:"The member's expiration date for this Safe. For members that do not have an expiration date, this value will be null"`
	IsExpiredMembershipEnabled bool                             `json:"is_expired_membership_enabled,omitempty" mapstructure:"is_expired_membership_enabled" desc:"Whether or not the membership for the Safe is expired. For expired members, the value is True"`
	IsPredefinedUser           bool                             `json:"is_predefined_user" mapstructure:"is_predefined_user" desc:"Whether the member is a predefined Vault user or group"`
	IsReadOnly                 bool                             `json:"is_read_only" mapstructure:"is_read_only" desc:"Whether or not the current user can update the permissions of the member"`
	Permissions                IdsecPCloudSafeMemberPermissions `json:"permissions" mapstructure:"permissions" desc:"The permissions that the user or group has on this Safe"`
	PermissionSet              string                           `json:"permission_set" mapstructure:"permission_set" desc:"Permission set type the permissions are set to (connect_only,read_only,approver,accounts_manager,full,custom)" default:"custom" choices:"connect_only,read_only,approver,accounts_manager,full,custom"`
}
