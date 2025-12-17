package db

import (
	"archive/zip"
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"

	jwt "github.com/golang-jwt/jwt/v5"
	"github.com/cyberark/idsec-sdk-golang/pkg/auth"
	"github.com/cyberark/idsec-sdk-golang/pkg/common"
	"github.com/cyberark/idsec-sdk-golang/pkg/common/isp"
	"github.com/cyberark/idsec-sdk-golang/pkg/services"
	dbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/db/models"
	"github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso"
	ssomodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/sso/models"
	workspacesdbmodels "github.com/cyberark/idsec-sdk-golang/pkg/services/sia/workspaces/db/models"
)

const (
	assetsURL            = "api/adb/guidance/generate"
	defaultSqlcmdTimeout = 60
)

// IdsecSIADBService is a struct that implements the IdsecService interface and provides functionality for DB service of SIA.
type IdsecSIADBService struct {
	services.IdsecService
	*services.IdsecBaseService
	ispAuth    *auth.IdsecISPAuth
	client     *isp.IdsecISPServiceClient
	ssoService *sso.IdsecSIASSOService
}

// NewIdsecSIADBService creates a new instance of IdsecSIADBService with the provided authenticators.
func NewIdsecSIADBService(authenticators ...auth.IdsecAuth) (*IdsecSIADBService, error) {
	dbService := &IdsecSIADBService{}
	var dbServiceInterface services.IdsecService = dbService
	baseService, err := services.NewIdsecBaseService(dbServiceInterface, authenticators...)
	if err != nil {
		return nil, err
	}
	ispBaseAuth, err := baseService.Authenticator("isp")
	if err != nil {
		return nil, err
	}
	ispAuth := ispBaseAuth.(*auth.IdsecISPAuth)
	client, err := isp.FromISPAuth(ispAuth, "dpa", ".", "", dbService.refreshSIAAuth)
	if err != nil {
		return nil, err
	}
	dbService.client = client
	dbService.ispAuth = ispAuth
	dbService.IdsecBaseService = baseService
	dbService.ssoService, err = sso.NewIdsecSIASSOService(ispAuth)
	if err != nil {
		return nil, err
	}
	return dbService, nil
}

func (s *IdsecSIADBService) refreshSIAAuth(client *common.IdsecClient) error {
	err := isp.RefreshClient(client, s.ispAuth)
	if err != nil {
		return err
	}
	return nil
}

func (s *IdsecSIADBService) proxyAddress(dbType string) (string, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(s.client.GetToken(), jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	return fmt.Sprintf("%s.%s.%s", claims["subdomain"], dbType, claims["platform_domain"]), nil
}

func (s *IdsecSIADBService) connectionString(targetAddress string, targetUsername string, networkName string) (string, error) {
	parsedToken, _, err := new(jwt.Parser).ParseUnverified(s.client.GetToken(), jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	claims := parsedToken.Claims.(jwt.MapClaims)
	addressNetwork := targetAddress
	if networkName != "" {
		addressNetwork = fmt.Sprintf("%s#%s", targetAddress, networkName)
	}
	if targetUsername != "" {
		return fmt.Sprintf("%s#%s@%s@%s", claims["unique_name"], claims["subdomain"], targetUsername, addressNetwork), nil
	}
	return fmt.Sprintf("%s#%s@%s", claims["unique_name"], claims["subdomain"], addressNetwork), nil
}

func (s *IdsecSIADBService) addToPgPass(username, address, password string) error {
	passFormat := fmt.Sprintf("%s:*:*:%s:%s", address, username, password)
	path := fmt.Sprintf("%s%s.pgpass", os.Getenv("HOME"), string(os.PathSeparator))
	flags := os.O_RDWR | os.O_APPEND
	if _, err := os.Stat(path); os.IsNotExist(err) {
		flags = os.O_RDWR | os.O_CREATE
	}

	file, err := os.OpenFile(path, flags, 0600)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			s.Logger.Warning("Error closing pgpass file: %v", err)
		}
	}(file)
	var lines []string

	scanner := bufio.NewScanner(file)
	found := false
	for scanner.Scan() {
		line := scanner.Text()
		if line == passFormat {
			found = true
		}
		lines = append(lines, line)
	}

	if !found {
		lines = append(lines, passFormat)
	}

	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
}

func (s *IdsecSIADBService) removeFromPgPass(username, address, password string) error {
	passFormat := fmt.Sprintf("%s:*:*:%s:%s", address, username, password)
	path := fmt.Sprintf("%s%s.pgpass", os.Getenv("HOME"), string(os.PathSeparator))

	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	file, err := os.OpenFile(path, os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer func(file *os.File) {
		err := file.Close()
		if err != nil {
			s.Logger.Warning("Error closing pgpass file: %v", err)
		}
	}(file)

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		if line != passFormat {
			lines = append(lines, line)
		}
	}
	return os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0600)
}

func (s *IdsecSIADBService) createMyLoginCnf(username string, address string, password string) (string, error) {
	tempFile, err := os.CreateTemp("", "mylogin.cnf")
	if err != nil {
		return "", err
	}
	defer tempFile.Close() //nolint:errcheck
	config := fmt.Sprintf("[client]\nuser = '%s'\npassword = '%s'\nhost = '%s'\n", username, password, address)
	if _, err := tempFile.Write([]byte(config)); err != nil {
		return "", err
	}
	if err := os.Chmod(tempFile.Name(), 0600); err != nil {
		return "", err
	}
	return tempFile.Name(), nil
}

func (s *IdsecSIADBService) execute(commandLine string) error {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd.exe", "/C", commandLine)
	} else {
		cmd = exec.Command("sh", "-c", commandLine)
	}
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	return cmd.Run()
}

func (s *IdsecSIADBService) generateAssets(
	assetType string,
	connectionMethod string,
	responseFormat string,
	generationHints map[string]interface{},
	includeSSO bool,
	resourceType string,
) (interface{}, error) {
	assetsRequest := map[string]interface{}{
		"asset_type":        assetType,
		"connection_method": connectionMethod,
		"response_format":   responseFormat,
		"generation_hints":  generationHints,
	}
	if includeSSO {
		assetsRequest["include_sso"] = includeSSO
	}
	if resourceType != "" {
		assetsRequest["resource_type"] = resourceType
	}
	response, err := s.client.Post(context.Background(), assetsURL, assetsRequest)
	if err != nil {
		return nil, err
	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			common.GlobalLogger.Warning("Error closing response body")
		}
	}(response.Body)
	if response.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to generate assets - [%d] - [%s]", response.StatusCode, common.SerializeResponseToJSON(response.Body))
	}
	if responseFormat == dbmodels.ResponseFormatRaw {
		respBytes, err := io.ReadAll(response.Body)
		if err != nil {
			return nil, fmt.Errorf("failed to read response body: %v", err)
		}
		return string(respBytes), nil
	}
	generatedAssets, err := common.DeserializeJSONSnake(response.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize response body: %v", err)
	}
	return generatedAssets, nil
}

// Psql executes a PostgreSQL command using the provided execution parameters.
func (s *IdsecSIADBService) Psql(psqlExecution *dbmodels.IdsecSIADBPsqlExecution) error {
	proxyAddress, err := s.proxyAddress("postgres")
	if err != nil {
		return err
	}
	connectionString, err := s.connectionString(psqlExecution.TargetAddress, psqlExecution.TargetUsername, psqlExecution.NetworkName)
	if err != nil {
		return err
	}
	password, err := s.ssoService.ShortLivedPassword(&ssomodels.IdsecSIASSOGetShortLivedPassword{
		Service: "DPA-DB",
	})
	if err != nil {
		return err
	}
	executionAction := fmt.Sprintf("%s \"host=%s user=%s\"", psqlExecution.PsqlPath, proxyAddress, connectionString)

	if err := s.addToPgPass(connectionString, proxyAddress, password); err != nil {
		return err
	}
	defer func(s *IdsecSIADBService, username, address, password string) {
		err := s.removeFromPgPass(username, address, password)
		if err != nil {
			s.Logger.Warning("Error removing password from pgpass: %v", err)
		}
	}(s, connectionString, proxyAddress, password)
	return s.execute(executionAction)
}

// Mysql executes a MySQL command using the provided execution parameters.
func (s *IdsecSIADBService) Mysql(mysqlExecution *dbmodels.IdsecSIADBMysqlExecution) error {
	proxyAddress, err := s.proxyAddress("mysql")
	if err != nil {
		return err
	}
	connectionString, err := s.connectionString(mysqlExecution.TargetAddress, mysqlExecution.TargetUsername, mysqlExecution.NetworkName)
	if err != nil {
		return err
	}
	password, err := s.ssoService.ShortLivedPassword(&ssomodels.IdsecSIASSOGetShortLivedPassword{
		Service: "DPA-DB",
	})
	if err != nil {
		return err
	}
	tempCnfLogin, err := s.createMyLoginCnf(connectionString, proxyAddress, password)
	if err != nil {
		return err
	}
	executionAction := fmt.Sprintf("%s --defaults-file=%s", mysqlExecution.MysqlPath, tempCnfLogin)
	defer func() {
		err := os.Remove(tempCnfLogin)
		if err != nil {
			s.Logger.Warning("Error removing temporary .mylogin.cnf file: %v", err)
		}
	}()
	return s.execute(executionAction)
}

// Sqlcmd executes a sqlcmd command using the provided execution parameters.
func (s *IdsecSIADBService) Sqlcmd(sqlcmdExecution *dbmodels.IdsecSIADBSqlcmdExecution) error {
	proxyAddress, err := s.proxyAddress("mssql")
	if err != nil {
		return err
	}
	connectionString, err := s.connectionString(sqlcmdExecution.TargetAddress, sqlcmdExecution.TargetUsername, sqlcmdExecution.NetworkName)
	if err != nil {
		return err
	}
	password, err := s.ssoService.ShortLivedPassword(&ssomodels.IdsecSIASSOGetShortLivedPassword{
		Service: "DPA-DB",
	})
	if err != nil {
		return err
	}
	executionAction := fmt.Sprintf("%s -U %s -S %s -l %d -P%s", sqlcmdExecution.SqlcmdPath, connectionString, proxyAddress, defaultSqlcmdTimeout, password)
	return s.execute(executionAction)
}

// GenerateOracleTnsNames generates Oracle TNS names and writes them to the specified folder.
func (s *IdsecSIADBService) GenerateOracleTnsNames(generateOracleAssets *dbmodels.IdsecSIADBOracleGenerateAssets) error {
	s.Logger.Info("Generating Oracle TNS names")
	assetsData, err := s.generateAssets(
		dbmodels.AssetTypeOracleTNSAssets,
		generateOracleAssets.ConnectionMethod,
		generateOracleAssets.ResponseFormat,
		map[string]interface{}{"folder": generateOracleAssets.Folder},
		generateOracleAssets.IncludeSSO,
		workspacesdbmodels.FamilyTypeOracle,
	)
	if err != nil {
		return err
	}
	if assetsDataMap, ok := assetsData.(map[string]interface{}); ok {
		assetsData = assetsDataMap["generated_assets"]
	}
	decodedAssets, err := base64.StdEncoding.DecodeString(assetsData.(string))
	if err != nil {
		return err
	}
	if _, err := os.Stat(generateOracleAssets.Folder); os.IsNotExist(err) {
		if err := os.MkdirAll(generateOracleAssets.Folder, 0755); err != nil {
			return err
		}
	}
	if !generateOracleAssets.Unzip {
		filePath := filepath.Join(generateOracleAssets.Folder, "oracle_assets.zip")
		if err := os.WriteFile(filePath, decodedAssets, 0644); err != nil {
			return err
		}
	} else {
		zipReader, err := zip.NewReader(bytes.NewReader(decodedAssets), int64(len(decodedAssets)))
		if err != nil {
			return err
		}
		for _, file := range zipReader.File {
			filePath := filepath.Join(generateOracleAssets.Folder, file.Name)
			if file.FileInfo().IsDir() {
				if err := os.MkdirAll(filePath, 0755); err != nil {
					return err
				}
				continue
			}
			outFile, err := os.OpenFile(filePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, file.Mode())
			if err != nil {
				return err
			}
			defer outFile.Close() //nolint:errcheck
			rc, err := file.Open()
			if err != nil {
				return err
			}
			defer rc.Close() //nolint:errcheck
			_, err = io.Copy(outFile, rc)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

// GenerateProxyFullChain generates a proxy full chain asset and writes it to the specified folder.
func (s *IdsecSIADBService) GenerateProxyFullChain(generateProxyFullChain *dbmodels.IdsecSIADBProxyFullChainGenerateAssets) error {
	s.Logger.Info("Generating proxy full chain")

	assetsData, err := s.generateAssets(
		dbmodels.AssetTypeProxyFullChain,
		generateProxyFullChain.ConnectionMethod,
		generateProxyFullChain.ResponseFormat,
		nil,
		false,
		"",
	)
	if err != nil {
		return err
	}
	if assetsDataMap, ok := assetsData.(map[string]interface{}); ok {
		assetsData = assetsDataMap["generated_assets"]
	}
	if _, err := os.Stat(generateProxyFullChain.Folder); os.IsNotExist(err) {
		if err := os.MkdirAll(generateProxyFullChain.Folder, 0755); err != nil {
			return err
		}
	}

	filePath := filepath.Join(generateProxyFullChain.Folder, "proxy_fullchain.pem")
	if err := os.WriteFile(filePath, []byte(assetsData.(string)), 0644); err != nil {
		return err
	}

	return nil
}

// ServiceConfig returns the service configuration for the IdsecSIADBService.
func (s *IdsecSIADBService) ServiceConfig() services.IdsecServiceConfig {
	return ServiceConfig
}
