package models

import (
	"errors"
)

// Possible authentication methods for database instances in DB Policy.
const (
	AuthMethodLDAPAuth       = "ldap_auth"
	AuthMethodDBAuth         = "db_auth"
	AuthMethodOracleAuth     = "oracle_auth"
	AuthMethodMongoAuth      = "mongo_auth"
	AuthMethodSQLServerAuth  = "sqlserver_auth"
	AuthMethodRDSIAMUserAuth = "rds_iam_user_auth"
)

// IdsecPolicyDBInstanceTarget represents a database instance target in the DB Policy.
type IdsecPolicyDBInstanceTarget struct {
	InstanceName         string `json:"instance_name" mapstructure:"instance_name" flag:"instance-name" desc:"The name of the database instance." validate:"min=1,max=256"`
	InstanceType         string `json:"instance_type" mapstructure:"instance_type" flag:"instance-type" desc:"The database type of the database instance." choices:"Postgres,Oracle,MSSQL,MySQL,MariaDB,DB2,Mongo,Unknown"`
	InstanceID           string `json:"instance_id" mapstructure:"instance_id" flag:"instance-id" desc:"The ID of the database instance." validate:"min=1,max=256"`
	AuthenticationMethod string `json:"authentication_method" mapstructure:"authentication_method" flag:"authentication-method" desc:"The authentication method corresponding to the profile." choices:"ldap_auth,db_auth,oracle_auth,mongo_auth,sqlserver_auth,rds_iam_user_auth"`

	// Profiles, only one of these will be set based on the authentication method.
	// Note that the API has a single profiles field, but we separate them here for clarity and easier usage.
	LDAPAuthProfile       *IdsecPolicyDBLDAPAuthProfile       `json:"ldap_auth_profile,omitempty" mapstructure:"ldap_auth_profile,omitempty" flag:"ldap-auth-profile" desc:"The LDAP authentication profile for the database instance."`
	DBAuthProfile         *IdsecPolicyDBDBAuthProfile         `json:"db_auth_profile,omitempty" mapstructure:"db_auth_profile,omitempty" flag:"db-auth-profile" desc:"The local database authentication profile for the database instance."`
	OracleAuthProfile     *IdsecPolicyDBOracleAuthProfile     `json:"oracle_auth_profile,omitempty" mapstructure:"oracle_auth_profile,omitempty" flag:"oracle-auth-profile" desc:"The Oracle database authentication profile for the database instance."`
	MongoAuthProfile      *IdsecPolicyDBMongoAuthProfile      `json:"mongo_auth_profile,omitempty" mapstructure:"mongo_auth_profile,omitempty" flag:"mongo-auth-profile" desc:"The MongoDB authentication profile for the database instance."`
	SQLServerAuthProfile  *IdsecPolicyDBSqlServerAuthProfile  `json:"sqlserver_auth_profile,omitempty" mapstructure:"sqlserver_auth_profile,omitempty" flag:"sqlserver-auth-profile" desc:"The SQL Server authentication profile for the database instance."`
	RDSIAMUserAuthProfile *IdsecPolicyDBRDSIAMUserAuthProfile `json:"rds_iam_user_auth_profile,omitempty" mapstructure:"rds_iam_user_auth_profile,omitempty" flag:"rds-iam-user-auth-profile" desc:"The RDS IAM User authentication profile for the database instance."`
}

// SerializeProfile serializes the profile of the instance target based on the authentication method.
func (s *IdsecPolicyDBInstanceTarget) SerializeProfile() (map[string]interface{}, error) {
	switch s.AuthenticationMethod {
	case AuthMethodLDAPAuth:
		if s.LDAPAuthProfile != nil {
			return s.LDAPAuthProfile.Serialize(), nil
		}
		return nil, errors.New("ldap authentication profile is required for LDAP authentication method")
	case AuthMethodDBAuth:
		if s.DBAuthProfile != nil {
			return s.DBAuthProfile.Serialize(), nil
		}
		return nil, errors.New("local DB authentication profile is required for DB authentication method")
	case AuthMethodOracleAuth:
		if s.OracleAuthProfile != nil {
			return s.OracleAuthProfile.Serialize(), nil
		}
		return nil, errors.New("oracle DB authentication profile is required for Oracle authentication method")
	case AuthMethodMongoAuth:
		if s.MongoAuthProfile != nil {
			return s.MongoAuthProfile.Serialize(), nil
		}
		return nil, errors.New("mongodb authentication profile is required for MongoDB authentication method")
	case AuthMethodSQLServerAuth:
		if s.SQLServerAuthProfile != nil {
			return s.SQLServerAuthProfile.Serialize(), nil
		}
		return nil, errors.New("SQL Server authentication profile is required for SQL Server authentication method")
	case AuthMethodRDSIAMUserAuth:
		if s.RDSIAMUserAuthProfile != nil {
			return s.RDSIAMUserAuthProfile.Serialize(), nil
		}
		return nil, errors.New("RDS IAM User authentication profile is required for RDS IAM User authentication method")
	default:
		return nil, errors.New("unknown authentication method")
	}
}

// DeserializeProfile populates the profile of the instance target based on the authentication method.
func (s *IdsecPolicyDBInstanceTarget) DeserializeProfile(data map[string]interface{}) error {
	switch s.AuthenticationMethod {
	case AuthMethodLDAPAuth:
		if s.LDAPAuthProfile == nil {
			s.LDAPAuthProfile = &IdsecPolicyDBLDAPAuthProfile{}
		}
		return s.LDAPAuthProfile.Deserialize(data)
	case AuthMethodDBAuth:
		if s.DBAuthProfile == nil {
			s.DBAuthProfile = &IdsecPolicyDBDBAuthProfile{}
		}
		return s.DBAuthProfile.Deserialize(data)
	case AuthMethodOracleAuth:
		if s.OracleAuthProfile == nil {
			s.OracleAuthProfile = &IdsecPolicyDBOracleAuthProfile{}
		}
		return s.OracleAuthProfile.Deserialize(data)
	case AuthMethodMongoAuth:
		if s.MongoAuthProfile == nil {
			s.MongoAuthProfile = &IdsecPolicyDBMongoAuthProfile{}
		}
		return s.MongoAuthProfile.Deserialize(data)
	case AuthMethodSQLServerAuth:
		if s.SQLServerAuthProfile == nil {
			s.SQLServerAuthProfile = &IdsecPolicyDBSqlServerAuthProfile{}
		}
		return s.SQLServerAuthProfile.Deserialize(data)
	case AuthMethodRDSIAMUserAuth:
		if s.RDSIAMUserAuthProfile == nil {
			s.RDSIAMUserAuthProfile = &IdsecPolicyDBRDSIAMUserAuthProfile{}
		}
		return s.RDSIAMUserAuthProfile.Deserialize(data)
	default:
		return errors.New("unknown authentication method")
	}
}

// ClearProfileFromData clears the profile data from the provided map based on the authentication method.
func (s *IdsecPolicyDBInstanceTarget) ClearProfileFromData(data map[string]interface{}) {
	switch s.AuthenticationMethod {
	case AuthMethodLDAPAuth:
		delete(data, "ldap_auth_profile")
		delete(data, "ldapAuthProfile")
	case AuthMethodDBAuth:
		delete(data, "db_auth_profile")
		delete(data, "dbAuthProfile")
	case AuthMethodOracleAuth:
		delete(data, "oracle_auth_profile")
		delete(data, "oracleAuthProfile")
	case AuthMethodMongoAuth:
		delete(data, "mongo_auth_profile")
		delete(data, "mongoAuthProfile")
	case AuthMethodSQLServerAuth:
		delete(data, "sqlserver_auth_profile")
		delete(data, "sqlserverAuthProfile")
	case AuthMethodRDSIAMUserAuth:
		delete(data, "rds_iam_user_auth_profile")
		delete(data, "rdsIamUserAuthProfile")
	default:
		return
	}
}
