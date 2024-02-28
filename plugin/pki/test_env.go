package pki

import (
	"context"
	r "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	vcertutil "github.com/Venafi/vcert/v5/pkg/util"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki/vpkierror"
	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

type venafiConfigString string

type testData struct {
	cert     string
	cn       string
	csrPK    []byte
	dnsEmail string
	//dnsIP added to alt_names to support some old browsers which can't parse IP Addresses x509 extension
	dnsIP string
	dnsNS string
	//onlyIP added IP Address x509 field
	onlyIP               string
	keyPassword          string
	privateKey           string
	provider             venafiConfigString
	signCSR              bool
	customFields         []string
	ttl                  time.Duration
	storeBy              string
	storePkey            bool
	serviceGeneratedCert bool
	privateKeyFormat     string
	minCertTimeLeft      time.Duration
	ignoreLocalStorage   bool
	serverTimeout        time.Duration
}

type issueTestData struct {
	minCertTimeLeft    time.Duration
	ignoreLocalStorage bool
}

const (
	venafiConfigTPP                         venafiConfigString = "TPP"
	venafiConfigTPPPredefined               venafiConfigString = "TPPPredefined"
	venafiConfigTPPRestricted               venafiConfigString = "TPPRestricted"
	venafiConfigCloud                       venafiConfigString = "Cloud"
	venafiConfigCloudPredefined             venafiConfigString = "CloudPredefined"
	venafiConfigCloudRestricted             venafiConfigString = "CloudRestricted"
	venafiConfigToken                       venafiConfigString = "TppToken"
	venafiConfigTokenPredefined             venafiConfigString = "TppTokenPredefined"
	venafiConfigTokenWithRefresh            venafiConfigString = "TppTokenWithRefresh"
	venafiConfigTokenWithOnlyOneRefresh     venafiConfigString = "TppTokenWithOnlyOneRefresh"
	venafiConfigTokenWithSecondRefresh      venafiConfigString = "TppTokenWithOnlySecondRefresh"
	venafiConfigTokenRestricted             venafiConfigString = "TppTokenRestricted"
	venafiConfigFake                        venafiConfigString = "Fake"
	venafiConfigFakeDeprecatedStoreByCN     venafiConfigString = "FakeDeprecatedStoreByCN"
	venafiConfigFakeDeprecatedStoreBySerial venafiConfigString = "venafiConfigFakeDeprecatedStoreBySerial"
	venafiConfigFakeStoreByCN               venafiConfigString = "venafiConfigFakeStoreByCN"
	venafiConfigFakeStoreBySerial           venafiConfigString = "venafiConfigFakeStoreBySerial"
	venafiConfigFakeNoStore                 venafiConfigString = "venafiConfigFakeNoStore"
	venafiConfigFakeNoStorePKey             venafiConfigString = "venafiConfigFakeNoStorePKey"
	venafiConfigMixedTppAndCloud            venafiConfigString = "MixedTppCloud"
	venafiConfigMixedTppAndToken            venafiConfigString = "MixedTppToken"
	venafiConfigMixedTokenAndCloud          venafiConfigString = "MixedTokenCloud"
	venafiVenafiConfigFake                  venafiConfigString = "VenafiFake"
	venafiRoleConfig                        venafiConfigString = "Role"
	venafiRoleWithZoneConfig                venafiConfigString = "venafiRoleWithZone"
	venafiRoleWithVenafiSecretConfig        venafiConfigString = "venafiVenafiSecretZone"
)

var venafiTestRoleConfig = map[string]interface{}{
	"venafi_secret": "",
}

var venafiTestTPPConfig = map[string]interface{}{
	"url":               os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestTPPConfigPredefined = map[string]interface{}{
	"url":               "https://tpp.example.com/vedsdk",
	"tpp_user":          "admin",
	"tpp_password":      "strongPassword",
	"zone":              "devops\\vcert",
	"trust_bundle_file": "/opt/venafi/bundle.pem",
}

var venafiTestTPPConfigRestricted = map[string]interface{}{
	"url":               os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE_RESTRICTED"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestCloudConfig = map[string]interface{}{
	"url":    os.Getenv("CLOUD_URL"),
	"apikey": os.Getenv("CLOUD_APIKEY"),
	"zone":   os.Getenv("CLOUD_ZONE"),
}

var venafiTestCloudConfigPredefined = map[string]interface{}{
	"apikey": "xxxx-xxxxx-xxxxxx-xxxxxx",
	"zone":   "xxxxx-xxxxx-xxxxxx-xxxxxx-xxxx",
}

var venafiTestCloudConfigRestricted = map[string]interface{}{
	"url":    os.Getenv("CLOUD_URL"),
	"apikey": os.Getenv("CLOUD_APIKEY"),
	"zone":   os.Getenv("CLOUD_ZONE_RESTRICTED"),
}

var venafiTestTokenConfig = map[string]interface{}{
	"url":               os.Getenv("TPP_TOKEN_URL"),
	"access_token":      os.Getenv("TPP_ACCESS_TOKEN"),
	"zone":              os.Getenv("TPP_ZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestTokenConfigForRoleZone = map[string]interface{}{
	"zone": os.Getenv("TPP_ZONE2"),
}

var venafiTestTokenConfigForVenafiSecretZone = map[string]interface{}{}

var venafiTestTokenConfigPredefined = map[string]interface{}{
	"url":               "https://tpp.example.com",
	"access_token":      "admin",
	"zone":              "devops\\vcert",
	"trust_bundle_file": "/opt/venafi/bundle.pem",
}

var venafiTestConfigTokenWithRefresh = map[string]interface{}{
	"url":               "https://tpp.example.com",
	"access_token":      "admin",
	"refresh_token":     "refresh1",
	"refresh_token_2":   "refresh2",
	"zone":              "devops\\vcert",
	"trust_bundle_file": "/opt/venafi/bundle.pem",
	"fakemode":          true,
}

var venafiTestConfigTokenWithOnlyOneRefresh = map[string]interface{}{
	"url":               "https://tpp.example.com",
	"access_token":      "admin",
	"refresh_token":     "refresh1",
	"zone":              "devops\\vcert",
	"trust_bundle_file": "/opt/venafi/bundle.pem",
}

var venafiTestConfigTokenWithSecondRefresh = map[string]interface{}{
	"url":               "https://tpp.example.com",
	"access_token":      "admin",
	"refresh_token_2":   "refresh2",
	"zone":              "devops\\vcert",
	"trust_bundle_file": "/opt/venafi/bundle.pem",
}

var venafiTestTokenConfigRestricted = map[string]interface{}{
	"url":               os.Getenv("TPP_TOKEN_URL"),
	"access_token":      os.Getenv("TPP_ACCESS_TOKEN"),
	"zone":              os.Getenv("TPP_ZONE_RESTRICTED"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestFakeConfigDeprecatedStoreByCN = map[string]interface{}{
	"generate_lease":       true,
	"store_by_cn":          true,
	"store_pkey":           true,
	"ignore_local_storage": true,
}

var venafiTestFakeConfigDeprecatedStoreBySerial = map[string]interface{}{
	"generate_lease":       true,
	"store_by_serial":      true,
	"store_pkey":           true,
	"ignore_local_storage": true,
}

var venafiTestFakeConfigStoreByCN = map[string]interface{}{
	"generate_lease":       true,
	"store_by":             "cn",
	"store_pkey":           true,
	"ignore_local_storage": true,
}

var venafiTestFakeConfigStoreBySerial = map[string]interface{}{
	"generate_lease":       true,
	"store_by":             "serial",
	"store_pkey":           true,
	"ignore_local_storage": true,
}

var venafiTestFakeConfig = map[string]interface{}{
	"generate_lease":       true,
	"store_pkey":           true,
	"ignore_local_storage": true,
}

var venafiTestFakeConfigNoStore = map[string]interface{}{
	"generate_lease":       true,
	"no_store":             true,
	"ignore_local_storage": true,
}

var venafiTestFakeConfigNoStorePKey = map[string]interface{}{
	"generate_lease":       true,
	"store_pkey":           false,
	"ignore_local_storage": true,
}

var venafiTestMixedTppAndCloudConfig = map[string]interface{}{
	"url":      "xxxxxxxxxxx",
	"apikey":   "xxxxxxxxxxxxxxxx",
	"tpp_user": "admin",
	"zone":     "devops\\vcert",
}

var venafiTestMixedTppAndTokenConfig = map[string]interface{}{
	"url":          "xxxxxxxxxxx",
	"tpp_user":     "admin",
	"tpp_password": "weakPassword",
	"access_token": "xxxxxxxxxx==",
	"zone":         "devops\\vcert",
}

var venafiTestMixedTokenAndCloudConfig = map[string]interface{}{
	"url":          "xxxxxxxxxxx",
	"access_token": "xxxxxxxxxx==",
	"apikey":       "xxxxxxxxxxxxxxxx",
	"zone":         "devops\\vcert",
}

var venafiVenafiTestFakeConfig = map[string]interface{}{
	"fakemode": true,
}

type testEnv struct {
	Backend           logical.Backend
	Context           context.Context
	Storage           logical.Storage
	TestRandString    string
	RoleName          string
	CertificateSerial string
	CertId            string
	VenafiSecretName  string
}

func (e *testEnv) writeRoleToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)

	//Adding Venafi secret reference to Role
	roleData["venafi_secret"] = e.VenafiSecretName
	//Removing the zone from the data, as the Venafi secret zone must be used
	roleData["zone"] = ""

	ttl := strconv.Itoa(util.Role_ttl_test_property) + "h"
	roleData["ttl"] = ttl
	issuerHint := vcertutil.IssuerHintMicrosoft
	roleData["issuer_hint"] = issuerHint.String()

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create role, %#v", resp)
	}
}

func (e *testEnv) writeRoleToBackendWithData(t *testing.T, configString venafiConfigString, data testData) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)

	//Adding Venafi secret reference to Role
	roleData["venafi_secret"] = e.VenafiSecretName
	//Removing the zone from the data, as the Venafi secret zone must be used
	roleData["zone"] = ""

	ttl := strconv.Itoa(util.Role_ttl_test_property) + "h"
	if &data.ttl != nil {
		ttl = data.ttl.String()
	}
	roleData["ttl"] = ttl
	issuerHint := vcertutil.IssuerHintMicrosoft
	roleData["issuer_hint"] = issuerHint.String()
	if data.storeBy != "" {
		roleData["store_by"] = data.storeBy
	}

	if &data.ignoreLocalStorage != nil {
		roleData["ignore_local_storage"] = data.ignoreLocalStorage
	} else {
		// Default's
		roleData["ignore_local_storage"] = false
	}

	if data.minCertTimeLeft > 0 {
		roleData["min_cert_time_left"] = data.minCertTimeLeft
	}

	if &data.storePkey != nil {
		roleData["store_pkey"] = data.storePkey
	}

	if &data.serviceGeneratedCert != nil {
		roleData["service_generated_cert"] = data.serviceGeneratedCert
	}

	if data.serverTimeout != 0 {
		roleData["server_timeout"] = data.serverTimeout
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create role, %#v", resp)
	}
}

func (e *testEnv) writeRoleWithZoneToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)

	//Adding Venafi secret reference to Role
	roleData["venafi_secret"] = e.VenafiSecretName

	ttl := strconv.Itoa(util.Role_ttl_test_property) + "h"
	roleData["ttl"] = ttl
	roleData["issuer_hint"] = vcertutil.IssuerHintMicrosoft

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create role, %#v", resp)
	}
}

func (e *testEnv) writeRoleWithPreventIssuanceToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)

	//Adding Venafi secret reference to Role
	roleData["venafi_secret"] = e.VenafiSecretName

	ttl := strconv.Itoa(util.Role_ttl_test_property) + "h"
	roleData["ttl"] = ttl
	roleData["issuer_hint"] = vcertutil.IssuerHintMicrosoft

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create role, %#v", resp)
	}
}

func (e *testEnv) failToWriteRoleToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && !resp.IsError() {
		t.Fatal("Role with mixed cloud api key and tpp url should fail to write")
	}

	errText := resp.Data["error"].(string)

	if errText != util.ErrorTextVenafiSecretEmpty {
		t.Fatalf("Expecting error with text %s but got %s", util.ErrorTextVenafiSecretEmpty, errText)
	}
}

func (e *testEnv) listRolesInBackend(t *testing.T) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "roles",
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list roles, %#v", resp)
	}

	if resp.Data["keys"] == nil {
		t.Fatalf("Expected there will be roles in the keys list")
	}

	if !util.SliceContains(resp.Data["keys"].([]string), e.RoleName) {
		t.Fatalf("expected role name %s in list %s", e.RoleName, resp.Data["keys"])
	}
}

func (e *testEnv) readRolesInBackend(t *testing.T, config map[string]interface{}) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp == nil {
		t.Fatalf("should be on output on reading the role %s, but response is nil: %#v", e.RoleName, resp)
	}

	if resp.IsError() {
		t.Fatalf("failed to read role %s, %#v", e.RoleName, resp)
	}

	sensitiveData := []string{"tpp_password", "apikey"}

	for k, v := range config {
		if util.SliceContains(sensitiveData, k) {
			if resp.Data[k] != nil {
				t.Fatalf("Sensitive data %s should be hidden", k)
			}
		} else {
			if resp.Data[k] == nil {
				t.Fatalf("Expected there will be value in %s field", k)
			}
			if k == "ttl" {
				timeInSeconds := resp.Data[k].(int64)
				duration := time.Duration(timeInSeconds) * time.Second
				hours := int(duration.Hours())
				hoursStr := strconv.Itoa(hours) + "h"
				if hoursStr != v {
					t.Fatalf("Expected %#v will be %#v", k, v)
				}

			} else if resp.Data[k] != v {
				t.Fatalf("Expected %#v will be %#v", k, v)
			}
		}
	}

}

func (e *testEnv) writeVenafiToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create venafi, %#v", resp)
	}
}

func (e *testEnv) failToWriteVenafiToBackend(t *testing.T, configString venafiConfigString, expectedError string) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && !resp.IsError() {
		t.Fatal("Venafi secret should fail have failed to write")
	}

	errText := resp.Data["error"].(string)

	if errText != expectedError {
		t.Fatalf("Expecting error with text %s but got %s", expectedError, errText)
	}
}

func (e *testEnv) listVenafiInBackend(t *testing.T) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "venafi",
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list venafi secrets, %#v", resp)
	}

	if resp.Data["keys"] == nil {
		t.Fatalf("Expected there will be venafi secrets in the keys list")
	}

	if !util.SliceContains(resp.Data["keys"].([]string), e.VenafiSecretName) {
		t.Fatalf("expected venafi secret name %s in list %s", e.VenafiSecretName, resp.Data["keys"])
	}
}

func (e *testEnv) readVenafiInBackend(t *testing.T, config map[string]interface{}) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp == nil {
		t.Fatalf("should be on output on reading the venafi secret %s, but response is nil: %#v", e.VenafiSecretName, resp)
	}

	if resp.IsError() {
		t.Fatalf("failed to read venafi %s, %#v", e.VenafiSecretName, resp)
	}

	sensitiveData := []string{"tpp_password", "apikey", "access_token", "refresh_token"}

	for k, v := range config {
		if util.SliceContains(sensitiveData, k) {
			if resp.Data[k] != "********" {
				t.Fatalf("Sensitive data %s should be hidden", k)
			}
		} else {
			if resp.Data[k] == nil {
				t.Fatalf("Expected there will be value in %s field", k)
			}

			if resp.Data[k] != v {
				t.Fatalf("Expected %#v will be %#v", k, v)
			}
		}
	}
}

func (e *testEnv) IssueCertificateAndSaveSerial(t *testing.T, data testData, configString venafiConfigString) {

	var issueData map[string]interface{}

	var altNames []string

	if data.dnsNS != "" {
		altNames = append(altNames, data.dnsNS)
	}
	if data.dnsEmail != "" {
		altNames = append(altNames, data.dnsEmail)
	}
	if data.dnsIP != "" {
		altNames = append(altNames, data.dnsIP)
	}

	if data.keyPassword != "" {
		issueData = map[string]interface{}{
			"common_name":        data.cn,
			"alt_names":          strings.Join(altNames, ","),
			"ip_sans":            []string{data.onlyIP},
			"key_password":       data.keyPassword,
			"private_key_format": "der",
		}
	} else {
		issueData = map[string]interface{}{
			"common_name":        data.cn,
			"alt_names":          strings.Join(altNames, ","),
			"ip_sans":            []string{data.onlyIP},
			"private_key_format": "der",
		}
	}

	if data.privateKeyFormat != "" {
		issueData["private_key_format"] = data.privateKeyFormat
	}

	if data.customFields != nil {
		issueData["custom_fields"] = strings.Join(data.customFields, ",")
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/" + e.RoleName,
		Storage:   e.Storage,
		Data:      issueData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	data.cert = resp.Data["certificate"].(string)
	if data.keyPassword != "" {
		encryptedKey := resp.Data["private_key"].(string)
		b, _ := pem.Decode([]byte(encryptedKey))
		b.Bytes, err = x509.DecryptPEMBlock(b, []byte(data.keyPassword))
		if err != nil {
			t.Fatal(err)
		}
		data.privateKey = string(pem.EncodeToMemory(b))
	} else {
		data.privateKey = resp.Data["private_key"].(string)
	}

	// it is needed to determine if we're checking cloud signed certificate in checkStandartCert
	data.provider = configString

	checkStandardCert(t, data)
	// save certificate serial for the next test
	e.CertificateSerial = resp.Data["serial_number"].(string)
}

func (e *testEnv) IssueCertificateAndSaveSerialParallelism(t *testing.T, data testData, configString venafiConfigString) string {
	// TODO: We need to refactor original function "IssueCertificateAndSaveSerial" to return serial and make according changes to dependant test
	var issueData map[string]interface{}

	var altNames []string

	if data.dnsNS != "" {
		altNames = append(altNames, data.dnsNS)
	}
	if data.dnsEmail != "" {
		altNames = append(altNames, data.dnsEmail)
	}
	if data.dnsIP != "" {
		altNames = append(altNames, data.dnsIP)
	}

	if data.keyPassword != "" {
		issueData = map[string]interface{}{
			"common_name":        data.cn,
			"alt_names":          strings.Join(altNames, ","),
			"ip_sans":            []string{data.onlyIP},
			"key_password":       data.keyPassword,
			"private_key_format": "der",
		}
	} else {
		issueData = map[string]interface{}{
			"common_name":        data.cn,
			"alt_names":          strings.Join(altNames, ","),
			"ip_sans":            []string{data.onlyIP},
			"private_key_format": "der",
		}
	}

	if data.privateKeyFormat != "" {
		issueData["private_key_format"] = data.privateKeyFormat
	}

	if data.customFields != nil {
		issueData["custom_fields"] = strings.Join(data.customFields, ",")
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/" + e.RoleName,
		Storage:   e.Storage,
		Data:      issueData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	data.cert = resp.Data["certificate"].(string)
	if data.keyPassword != "" {
		encryptedKey := resp.Data["private_key"].(string)
		b, _ := pem.Decode([]byte(encryptedKey))
		b.Bytes, err = x509.DecryptPEMBlock(b, []byte(data.keyPassword))
		if err != nil {
			t.Fatal(err)
		}
		data.privateKey = string(pem.EncodeToMemory(b))
	} else {
		data.privateKey = resp.Data["private_key"].(string)
	}

	// it is needed to determine if we're checking cloud signed certificate in checkStandartCert
	data.provider = configString

	checkStandardCert(t, data)
	serial := resp.Data["serial_number"].(string)
	return serial
}

func (e *testEnv) IssueCertificateAndSaveSerialWithIssuanceData(t *testing.T, data testData, configString venafiConfigString, issueTestData *issueTestData) {

	var issueData map[string]interface{}

	var altNames []string

	if data.dnsNS != "" {
		altNames = append(altNames, data.dnsNS)
	}
	if data.dnsEmail != "" {
		altNames = append(altNames, data.dnsEmail)
	}
	if data.dnsIP != "" {
		altNames = append(altNames, data.dnsIP)
	}

	issueData = map[string]interface{}{
		"common_name":        data.cn,
		"alt_names":          strings.Join(altNames, ","),
		"ip_sans":            []string{data.onlyIP},
		"private_key_format": "der",
	}
	if data.keyPassword != "" {
		issueData["private_key_format"] = "der"
	}

	if issueTestData != nil {
		issueData["ignore_local_storage"] = issueTestData.ignoreLocalStorage
		issueData["min_cert_time_left"] = issueTestData.minCertTimeLeft
	}

	if data.privateKeyFormat != "" {
		issueData["private_key_format"] = data.privateKeyFormat
	}

	if data.customFields != nil {
		issueData["custom_fields"] = strings.Join(data.customFields, ",")
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/" + e.RoleName,
		Storage:   e.Storage,
		Data:      issueData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	data.cert = resp.Data["certificate"].(string)
	if data.keyPassword != "" {
		encryptedKey := resp.Data["private_key"].(string)
		b, _ := pem.Decode([]byte(encryptedKey))
		b.Bytes, err = x509.DecryptPEMBlock(b, []byte(data.keyPassword))
		if err != nil {
			t.Fatal(err)
		}
		data.privateKey = string(pem.EncodeToMemory(b))
	} else {
		data.privateKey = resp.Data["private_key"].(string)
	}

	// it is needed to determine if we're checking cloud signed certificate in checkStandartCert
	data.provider = configString

	checkStandardCert(t, data)
	// save certificate serial for the next test
	e.CertificateSerial = resp.Data["serial_number"].(string)
}

func (e *testEnv) IssueCertificateAndValidateTTL(t *testing.T, data testData) {

	var issueData map[string]interface{}

	var altNames []string

	if data.dnsNS != "" {
		altNames = append(altNames, data.dnsNS)
	}
	if data.dnsEmail != "" {
		altNames = append(altNames, data.dnsEmail)
	}
	if data.dnsIP != "" {
		altNames = append(altNames, data.dnsIP)
	}

	if data.keyPassword != "" {
		issueData = map[string]interface{}{
			"common_name":  data.cn,
			"alt_names":    strings.Join(altNames, ","),
			"ip_sans":      []string{data.onlyIP},
			"key_password": data.keyPassword,
		}
	} else {
		issueData = map[string]interface{}{
			"common_name": data.cn,
			"alt_names":   strings.Join(altNames, ","),
			"ip_sans":     []string{data.onlyIP},
		}
	}
	expectedTTL := util.Role_ttl_test_property
	if data.ttl > 0 {
		issueData["ttl"] = strconv.Itoa(int(data.ttl.Hours())) + "h"
		expectedTTL = util.Ttl_test_property
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/" + e.RoleName,
		Storage:   e.Storage,
		Data:      issueData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	data.cert = resp.Data["certificate"].(string)

	//it is need to determine if we're checking cloud signed certificate in checkStandartCert
	p, _ := pem.Decode([]byte(data.cert))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}

	certValidUntil := cert.NotAfter.Format("2006-01-02")

	//need to convert local date on utc, since the certificate' NotAfter value we got on previous step, is on utc
	//so for comparing them we need to have both dates on utc.
	loc, _ := time.LoadLocation("UTC")
	utcNow := time.Now().In(loc)
	expectedValidDate := utcNow.AddDate(0, 0, expectedTTL/24).Format("2006-01-02")

	if expectedValidDate != certValidUntil {
		t.Fatalf("Expiration date is different than expected, expected: %s, but got %s: ", expectedValidDate, certValidUntil)
	}
}

func (e *testEnv) SignCertificate(t *testing.T, data testData, configString venafiConfigString) {

	//Generating CSR for test
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = data.cn
	if data.dnsNS != "" {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dnsNS)
	}

	if data.dnsIP != "" {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dnsIP)
	}

	if configString == venafiConfigFakeDeprecatedStoreByCN {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.cn)
	}

	if data.onlyIP != "" {
		certificateRequest.IPAddresses = []net.IP{net.ParseIP(data.onlyIP)}
	}

	if data.dnsIP != "" {
		certificateRequest.IPAddresses = append(certificateRequest.IPAddresses, net.ParseIP(data.dnsIP))
	}

	if data.dnsEmail != "" {
		certificateRequest.EmailAddresses = []string{data.dnsEmail}
	}

	//Generating pk for test
	priv, err := rsa.GenerateKey(r.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data.csrPK = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	csr, err := x509.CreateCertificateRequest(r.Reader, &certificateRequest, priv)
	if err != nil {
		csr = nil
	}
	pemCSR := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})))

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/" + e.RoleName,
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"csr": pemCSR,
		},
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)
	data.provider = configString

	checkStandardCert(t, data)
}

func (e *testEnv) SignCertificateWithTTL(t *testing.T, data testData, configString venafiConfigString) {

	//Generating CSR for test
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = data.cn
	if data.dnsNS != "" {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dnsNS)
	}

	if data.dnsIP != "" {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dnsIP)
	}

	if configString == venafiConfigFakeDeprecatedStoreByCN {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.cn)
	}

	if data.onlyIP != "" {
		certificateRequest.IPAddresses = []net.IP{net.ParseIP(data.onlyIP)}
	}

	if data.dnsIP != "" {
		certificateRequest.IPAddresses = append(certificateRequest.IPAddresses, net.ParseIP(data.dnsIP))
	}

	if data.dnsEmail != "" {
		certificateRequest.EmailAddresses = []string{data.dnsEmail}
	}

	//Generating pk for test
	priv, err := rsa.GenerateKey(r.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	data.csrPK = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)

	csr, err := x509.CreateCertificateRequest(r.Reader, &certificateRequest, priv)
	if err != nil {
		csr = nil
	}
	pemCSR := strings.TrimSpace(string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})))

	issueData := map[string]interface{}{
		"csr": pemCSR,
	}

	if data.ttl > 0 {

		issueData["ttl"] = strconv.Itoa(int(data.ttl.Hours())) + "h"

	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "sign/" + e.RoleName,
		Storage:   e.Storage,
		Data:      issueData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)

	//it is need to determine if we're checking cloud signed certificate in checkStandartCert
	p, _ := pem.Decode([]byte(data.cert))
	cert, err := x509.ParseCertificate(p.Bytes)
	if err != nil {
		t.Fatalf("%s", err)
	}

	certValidUntil := cert.NotAfter.Format("2006-01-02")

	//need to convert local date on utc, since the certificate' NotAfter value we got on previous step, is on utc
	//so for comparing them we need to have both dates on utc.
	loc, _ := time.LoadLocation("UTC")
	utcNow := time.Now().In(loc)
	expectedValidDate := utcNow.AddDate(0, 0, util.Ttl_test_property/24).Format("2006-01-02")

	if expectedValidDate != certValidUntil {
		t.Fatalf("Expiration date is different than expected, expected: %s, but got %s: ", expectedValidDate, certValidUntil)
	}

}

func (e *testEnv) ReadCertificate(t *testing.T, data testData, configString venafiConfigString, certId string) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cert/" + certId,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	if resp.Data["certificate"] == nil {
		t.Fatalf("expected a cert to be in read data")
	}

	if resp.Data["private_key"] == nil {
		t.Fatalf("expected a private_key to be in read data")
	}

	data.cert = resp.Data["certificate"].(string)
	data.privateKey = resp.Data["private_key"].(string)
	checkStandardCert(t, data)

}

func (e *testEnv) CheckThatThereIsNoCertificate(t *testing.T, certId string) {

	path := "cert/" + certId
	_, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      path,
		Storage:   e.Storage,
	})

	if err == nil {
		t.Fatal("should be no entry error if there is no certificate")
	}

	if !errors.As(err, &vpkierror.CertEntryNotFound{}) {
		t.Fatalf("error should contain %s substring but it is %s", vpkierror.CertEntryNotFound{EntryPath: path}, err.Error())
	}

}

func (e *testEnv) CheckThatThereIsNoPKey(t *testing.T, certId string) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cert/" + certId,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to read certificate, %#v", resp.Data["error"])
	}

	if resp == nil {
		t.Fatalf("should be on output on issue certificate, but response is nil: %#v", resp)
	}

	if resp.Data["private_key"] != "" {
		t.Fatalf("expected no private_key in the store")
	}

}

func (e *testEnv) ListCertificates(t *testing.T, data testData, configString venafiConfigString) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs",
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to list certificates, %#v", resp.Data["error"])
	}

	if resp.Data["keys"] == nil {
		t.Fatalf("certificate list should not be empty, but response data is empty: %#v", resp.Data)
	}

	//check that we can read certificate from list
	e.ReadCertificate(t, data, configString, resp.Data["keys"].([]string)[0])
}

func (e *testEnv) RevokeCertificate(t *testing.T, certId string) {

	dataKey := "certificate_uid"
	_, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "revoke/" + e.RoleName,
		Storage:   e.Storage,
		Data: map[string]interface{}{
			dataKey: certId,
		},
	})

	if err != nil {
		t.Fatal(err)
	}
}

func makeConfig(configString venafiConfigString) (roleData map[string]interface{}, err error) {

	switch configString {
	case venafiConfigFake:
		roleData = venafiTestFakeConfig
	case venafiConfigFakeDeprecatedStoreByCN:
		roleData = venafiTestFakeConfigDeprecatedStoreByCN
	case venafiConfigFakeDeprecatedStoreBySerial:
		roleData = venafiTestFakeConfigDeprecatedStoreBySerial
	case venafiConfigFakeStoreByCN:
		roleData = venafiTestFakeConfigStoreByCN
	case venafiConfigFakeStoreBySerial:
		roleData = venafiTestFakeConfigStoreBySerial
	case venafiConfigFakeNoStore:
		roleData = venafiTestFakeConfigNoStore
	case venafiConfigFakeNoStorePKey:
		roleData = venafiTestFakeConfigNoStorePKey
	case venafiConfigTPP:
		roleData = venafiTestTPPConfig
	case venafiConfigTPPPredefined:
		roleData = venafiTestTPPConfigPredefined
	case venafiConfigTPPRestricted:
		roleData = venafiTestTPPConfigRestricted
	case venafiConfigCloud:
		roleData = venafiTestCloudConfig
	case venafiConfigCloudPredefined:
		roleData = venafiTestCloudConfigPredefined
	case venafiConfigCloudRestricted:
		roleData = venafiTestCloudConfigRestricted
	case venafiConfigToken:
		roleData = venafiTestTokenConfig
	case venafiConfigTokenPredefined:
		roleData = venafiTestTokenConfigPredefined
	case venafiConfigTokenWithRefresh:
		roleData = venafiTestConfigTokenWithRefresh
	case venafiConfigTokenWithOnlyOneRefresh:
		roleData = venafiTestConfigTokenWithOnlyOneRefresh
	case venafiConfigTokenWithSecondRefresh:
		roleData = venafiTestConfigTokenWithSecondRefresh
	case venafiConfigTokenRestricted:
		roleData = venafiTestTokenConfigRestricted
	case venafiConfigMixedTppAndCloud:
		roleData = venafiTestMixedTppAndCloudConfig
	case venafiConfigMixedTppAndToken:
		roleData = venafiTestMixedTppAndTokenConfig
	case venafiConfigMixedTokenAndCloud:
		roleData = venafiTestMixedTokenAndCloudConfig
	case venafiVenafiConfigFake:
		roleData = venafiVenafiTestFakeConfig
	case venafiRoleConfig:
		roleData = venafiTestRoleConfig
	case venafiRoleWithZoneConfig:
		roleData = venafiTestTokenConfigForRoleZone
	case venafiRoleWithVenafiSecretConfig:
		roleData = venafiTestTokenConfigForVenafiSecretZone
	default:
		return roleData, fmt.Errorf("do not have config data for config %s", configString)
	}

	return roleData, nil

}

func (e *testEnv) FakeCreateRole(t *testing.T) {

	var config = venafiConfigFake
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeCreateVenafi(t *testing.T) {
	var config = venafiVenafiConfigFake
	e.writeVenafiToBackend(t, config)
}

func (e *testEnv) FakeCreateRoleDeprecatedStoreByCN(t *testing.T) {

	var config = venafiConfigFakeDeprecatedStoreByCN
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeCreateRoleDeprecatedStoreBySerial(t *testing.T) {

	var config = venafiConfigFakeDeprecatedStoreBySerial
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeCreateRoleStoreByCN(t *testing.T) {

	var config = venafiConfigFakeStoreByCN
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeCreateRoleStoreBySerial(t *testing.T) {

	var config = venafiConfigFakeStoreBySerial
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeCreateRoleNoStore(t *testing.T) {

	var config = venafiConfigFakeNoStore
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeCreateRoleNoStorePKey(t *testing.T) {

	var config = venafiConfigFakeNoStorePKey
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) CreateVenafiTPP(t *testing.T) {

	var config = venafiConfigTPPPredefined
	e.writeVenafiToBackend(t, config)

}

func (e *testEnv) CreateVenafiCloud(t *testing.T) {

	var config = venafiConfigCloudPredefined
	e.writeVenafiToBackend(t, config)

}

func (e *testEnv) CreateVenafiToken(t *testing.T) {

	var config = venafiConfigTokenPredefined
	e.writeVenafiToBackend(t, config)
}

func (e *testEnv) CreateVenafiTokenWithRefresh(t *testing.T) {

	var config = venafiConfigTokenWithRefresh
	e.writeVenafiToBackend(t, config)
}

func (e *testEnv) FailCreateVenafiTokenWithOnlyOneRefresh(t *testing.T) {
	var config = venafiConfigTokenWithOnlyOneRefresh
	e.failToWriteVenafiToBackend(t, config, util.ErrorTextNeed2RefreshTokens)
}

func (e *testEnv) FailCreateVenafiTokenWithOnlySecondRefreshSet(t *testing.T) {
	var config = venafiConfigTokenWithSecondRefresh
	e.failToWriteVenafiToBackend(t, config, util.ErrorTextNeed2RefreshTokens)
}

func (e *testEnv) CreateVenafiMixedTppAndCloud(t *testing.T) {

	var config = venafiConfigMixedTppAndCloud
	e.failToWriteVenafiToBackend(t, config, util.ErrorTextMixedTPPAndCloud)

}

func (e *testEnv) CreateVenafiMixedTppAndToken(t *testing.T) {

	var config = venafiConfigMixedTppAndToken
	e.failToWriteVenafiToBackend(t, config, util.ErrorTextMixedTPPAndToken)

}

func (e *testEnv) CreateVenafiMixedTokenAndCloud(t *testing.T) {

	var config = venafiConfigMixedTokenAndCloud
	e.failToWriteVenafiToBackend(t, config, util.ErrorTextMixedTokenAndCloud)

}

func (e *testEnv) DeleteVenafi(t *testing.T) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp)
	}

	resp, err = e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil {
		t.Fatalf("should be no output on reading the deleted venafi secret %s, but response is: %#v", e.VenafiSecretName, resp)
	}

}

func (e *testEnv) CreateRoleEmptyVenafi(t *testing.T) {

	var config = venafiRoleConfig
	e.failToWriteRoleToBackend(t, config)
}

func (e *testEnv) FakeCheckThatThereIsNoCertificate(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain

	e.CheckThatThereIsNoCertificate(t, util.NormalizeSerial(e.CertificateSerial))

}

func (e *testEnv) FakeCheckThatThereIsNoPKey(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain

	e.CheckThatThereIsNoPKey(t, util.NormalizeSerial(e.CertificateSerial))
}

func (e *testEnv) DeleteRole(t *testing.T) {

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatal(resp)
	}

	resp, err = e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "roles/" + e.RoleName,
		Storage:   e.Storage,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil {
		t.Fatalf("should be no output on reading the deleted role %s, but response is: %#v", e.RoleName, resp)
	}

}

func (e *testEnv) FakeListRole(t *testing.T) {
	e.listRolesInBackend(t)

}

func (e *testEnv) FakeReadRole(t *testing.T) {

	e.readRolesInBackend(t, venafiTestFakeConfig)

}

func (e *testEnv) FakeListVenafi(t *testing.T) {

	e.listVenafiInBackend(t)

}

func (e *testEnv) FakeReadVenafi(t *testing.T) {

	e.readVenafiInBackend(t, venafiVenafiTestFakeConfig)

}

func (e *testEnv) ReadVenafiTPP(t *testing.T) {

	e.readVenafiInBackend(t, venafiTestTPPConfigPredefined)

}

func (e *testEnv) ReadVenafiCloud(t *testing.T) {

	e.readVenafiInBackend(t, venafiTestCloudConfigPredefined)

}

func (e *testEnv) ReadVenafiToken(t *testing.T) {

	e.readVenafiInBackend(t, venafiTestTokenConfigPredefined)

}

func (e *testEnv) FakeIssueCertificateAndSaveSerial(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigFakeDeprecatedStoreByCN
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) FakeReadCertificateByCN(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigFakeDeprecatedStoreByCN
	e.ReadCertificate(t, data, config, data.cn)

}

func (e *testEnv) FakeReadCertificateBySerial(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigFakeDeprecatedStoreBySerial
	e.ReadCertificate(t, data, config, util.NormalizeSerial(e.CertificateSerial))

}

func (e *testEnv) FakeRevokeCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"

	e.RevokeCertificate(t, data.cn)

}

func (e *testEnv) FakeRevokeCertificateBySerial(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"
	serial := util.NormalizeSerial(e.CertificateSerial)

	e.RevokeCertificate(t, serial)

}

func (e *testEnv) FakeListCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigFakeDeprecatedStoreByCN
	e.ListCertificates(t, data, config)

}

func (e *testEnv) FakeIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigFakeDeprecatedStoreByCN

	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) FakeIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "password"

	var config = venafiConfigFakeDeprecatedStoreByCN

	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) FakeSignCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "-signed." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.onlyIP = "127.0.0.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "password"
	data.signCSR = true

	var config = venafiConfigFakeDeprecatedStoreByCN

	e.SignCertificate(t, data, config)
}

func (e *testEnv) TPPIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigTPP

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TPPIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "Pass0rd!"

	var config = venafiConfigTPP

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TPPIntegrationIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.onlyIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigTPPRestricted

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TPPIntegrationSignCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "127.0.0.1"
	data.onlyIP = "192.168.0.1"
	data.signCSR = true

	var config = venafiConfigTPP

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.SignCertificate(t, data, config)

}

func (e *testEnv) CloudIntegrationSignCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.signCSR = true

	var config = venafiConfigCloud

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.SignCertificate(t, data, config)

}

func (e *testEnv) CloudIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "www." + data.cn

	var config = venafiConfigCloud

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) CloudIntegrationIssueCertificateAndVerifyTTL(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "www." + data.cn

	var config = venafiConfigCloud

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndValidateTTL(t, data)
}

func (e *testEnv) CloudIntegrationIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "www." + data.cn

	var config = venafiConfigCloud

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) CloudIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "www." + data.cn
	data.keyPassword = "password"

	var config = venafiConfigCloud

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) TokenIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TokenIntegrationIssueCertificateAndValidateTTL(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndValidateTTL(t, data)

}

func (e *testEnv) TokenIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "Pass0rd!"

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TokenIntegrationIssueCertificateWithExtended(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "Pass0rd!"
	data.serverTimeout = time.Duration(3) * time.Minute

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TokenIntegrationIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.onlyIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigTokenRestricted

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TokenIntegrationSignCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "127.0.0.1"
	data.onlyIP = "192.168.0.1"
	data.signCSR = true

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.SignCertificate(t, data, config)

}

func (e *testEnv) TokenIntegrationSignCertificateWithCustomFields(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "127.0.0.1"
	data.onlyIP = "192.168.0.1"
	data.signCSR = true
	data.customFields = []string{"custom=vaultTest", "cfList=item2", "cfListMulti=tier1", "cfListMulti=tier4"}

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.SignCertificate(t, data, config)
}

func (e *testEnv) TokenIntegrationRevokeCertificateSerial(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "127.0.0.1"
	data.onlyIP = "192.168.0.1"
	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
	serial := util.NormalizeSerial(e.CertificateSerial)
	log.Println("Testing Serial:", serial)
	e.RevokeCertificate(t, serial)
}

func (e *testEnv) TokenIntegrationRevokeCertificateCN(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "127.0.0.1"
	data.onlyIP = "192.168.0.1"
	data.storeBy = "cn"
	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	e.RevokeCertificate(t, data.cn)
}

func (e *testEnv) TokenIntegrationSignWithTTLCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "127.0.0.1"
	data.onlyIP = "192.168.0.1"
	data.signCSR = true
	data.ttl = time.Duration(util.Ttl_test_property) * time.Hour

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.SignCertificateWithTTL(t, data, config)

}

func (e *testEnv) TokenIntegrationIssueCertificateWithCustomFields(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "Pass0rd!"
	data.customFields = []string{"custom=vaultTest", "cfList=item2", "cfListMulti=tier1", "cfListMulti=tier4"}

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) TokenIntegrationIssueCertificateWithTTLOnIssueData(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"
	data.keyPassword = "Pass0rd!"
	data.ttl = time.Duration(util.Ttl_test_property) * time.Hour

	var config = venafiConfigToken

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndValidateTTL(t, data)
}

func (e *testEnv) TokenEnrollWithRoleZone(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigToken
	var roleConfig = venafiRoleWithZoneConfig
	e.writeVenafiToBackend(t, config)
	e.writeRoleWithZoneToBackend(t, roleConfig)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) TokenEnrollWithVenafiSecretZone(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigToken
	var roleConfig = venafiRoleWithVenafiSecretConfig
	e.writeVenafiToBackend(t, config)
	e.writeRoleWithZoneToBackend(t, roleConfig)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) PreventReissuance(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// means that we went to issue another certificate which shouldn't have happened
		// as we intend to present the one in storage
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) NotPreventReissuance(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceCNwithExtraSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	data.dnsNS = data.dnsNS + ",alt2-" + data.cn
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since a new SAN DNS was provided in second run, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceCNandRemovingSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn + ",alt2-" + data.cn + ",alt3-" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	data.dnsNS = "alt-" + data.cn + ",alt2-" + data.cn
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since SAN DNS was removed in second run, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceCNnoSANSDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// means that we went to issue another certificate which shouldn't have happened
		// as we intend to present the one in storage
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) PreventReissuanceTTLnotValid(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since TTL is less than time we consider a certificate to be valid, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceTTLvalid(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// since TTL is within than time we consider a certificate to be valid, we should have not issued
		// another certificate, so serials should be equal
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) PreventReissuanceCNwithThreeSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn + "," + "alt2-" + data.cn + "," + "alt3" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) PreventReissuanceCNwithDifferentCNandThreeSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn + "," + "alt2-" + data.cn + "," + "alt3" + data.cn
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	data.cn = e.TestRandString
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceCNwithNoCNandThreeSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	commonName := randString + "." + domain
	data.cn = ""
	data.dnsNS = "alt-" + commonName + "," + "alt2-" + commonName + "," + "alt3" + commonName
	data.storeBy = "serial"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		t.Fatal("The serials are different")
	}
}

func checkStandardCert(t *testing.T, data testData) {
	var err error
	log.Println("Testing certificate:", data.cert)
	certPEMBlock, _ := pem.Decode([]byte(data.cert))
	if certPEMBlock == nil {
		t.Fatalf("Certificate data is nil in the pem block")
	}

	if !data.signCSR {
		log.Println("Testing private key:", data.privateKey)
		keyPEMBlock, _ := pem.Decode([]byte(data.privateKey))
		if keyPEMBlock == nil {
			t.Fatalf("Private key data is nil in thew private key")
		}
		_, err = tls.X509KeyPair([]byte(data.cert), []byte(data.privateKey))
		if err != nil {
			t.Fatalf("Error parsing certificate key pair: %s", err)
		}
	} else {
		_, err = tls.X509KeyPair([]byte(data.cert), []byte(data.csrPK))
		if err != nil {
			t.Fatalf("Error parsing certificate key pair: %s", err)
		}
	}

	parsedCertificate, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if parsedCertificate.Subject.CommonName != data.cn {
		t.Fatalf("Certificate common name expected to be %s but actualy it is %s", parsedCertificate.Subject.CommonName, data.cn)
	}

	// since data.dnsNS is a string as is being copying the behaviour
	// of the entry data, then it means it should have a string with values
	// separated by commas
	var wantDNSNames []string
	if data.dnsNS != "" {
		wantDNSNames = strings.Split(data.dnsNS, ",")
	}

	if data.dnsIP != "" {
		wantDNSNames = append(wantDNSNames, data.dnsIP)
	}

	ips := make([]net.IP, 0, 2)
	if data.onlyIP != "" {
		ips = append(ips, net.ParseIP(data.onlyIP))
	}
	if data.dnsIP != "" {
		ips = append(ips, net.ParseIP(data.dnsIP))
	}

	// since we allow setting only the CN (although the CN will be added to the SANs) during the request and we intend to
	// validate data only passed during the request, we make sure is not empty before passing the validation
	if len(wantDNSNames) > 0 {
		if !util.AreDNSNamesCorrect(parsedCertificate.DNSNames, []string{data.cn}, wantDNSNames) {
			t.Fatalf("Certificate Subject Alternative Names %v doesn't match to requested %v", parsedCertificate.DNSNames, wantDNSNames)
		}
	}

	if !util.SameIpSlice(ips, parsedCertificate.IPAddresses) {
		t.Fatalf("Certificate IPs %v doesn`t match requested %v", parsedCertificate.IPAddresses, ips)
	}

	if data.dnsEmail != "" {
		wantEmail := []string{data.dnsEmail}
		if !util.SameStringSlice(parsedCertificate.EmailAddresses, wantEmail) {
			t.Fatalf("Certificate emails %v doesn't match requested %v", parsedCertificate.EmailAddresses, wantEmail)
		}
	}

}

func (e *testEnv) PreventReissuanceLocal(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	commonName := data.cn
	data.dnsNS = "maria-" + commonName + "," + "rose-" + commonName + "," + "bob-" + commonName + "," + "bob-" + commonName + "," + "shina-" + commonName
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// means that we went to issue another certificate which shouldn't have happened
		// as we intend to present the one in storage
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) PreventReissuanceLocalWithIssuanceData(t *testing.T, data testData, config venafiConfigString, issuanceData issueTestData) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	commonName := data.cn
	data.dnsNS = "maria-" + commonName + "," + "rose-" + commonName + "," + "bob-" + commonName + "," + "bob-" + commonName + "," + "shina-" + commonName
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerialWithIssuanceData(t, data, config, &issuanceData)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerialWithIssuanceData(t, data, config, &issuanceData)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// means that we went to issue another certificate which shouldn't have happened
		// as we intend to present the one in storage
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) NotPreventReissuanceLocalWithIssuanceData(t *testing.T, data testData, config venafiConfigString, issuanceData issueTestData) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	commonName := data.cn
	data.dnsNS = "maria-" + commonName + "," + "rose-" + commonName + "," + "bob-" + commonName + "," + "bob-" + commonName + "," + "shina-" + commonName
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerialWithIssuanceData(t, data, config, &issuanceData)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerialWithIssuanceData(t, data, config, &issuanceData)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since a new SAN DNS was provided in second run, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) NotPreventReissuanceLocal(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	commonName := data.cn
	data.dnsNS = "maria-" + commonName + "," + "rose-" + commonName + "," + "bob-" + commonName + "," + "bob-" + commonName + "," + "shina-" + commonName
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceLocalCNwithExtraSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	data.dnsNS = data.dnsNS + ",alt2-" + data.cn
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since a new SAN DNS was provided in second run, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceLocalCNandRemovingSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn + ",alt2-" + data.cn + ",alt3-" + data.cn
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	data.dnsNS = "alt-" + data.cn + ",alt2-" + data.cn
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since SAN DNS was removed in second run, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceLocalCNandNoSANSDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// means that we went to issue another certificate which shouldn't have happened
		// as we intend to present the one in storage
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) PreventReissuanceLocalTTLnotValid(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		// since TTL is less than time we consider a certificate to be valid, we should have issued
		// another certificate, so serials should be different
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceLocalTTLvalid(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		// since TTL is within than time we consider a certificate to be valid, we should have not issued
		// another certificate, so serials should be equal
		t.Fatal("The serials are different")
	}
}
func (e *testEnv) PreventReissuanceLocalCNwithThreeSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn + "," + "alt2-" + data.cn + "," + "alt3" + data.cn
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) PreventReissuanceLocalCNwithDifferentCNandThreeSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn + "," + "alt2-" + data.cn + "," + "alt3" + data.cn
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	data.cn = e.TestRandString
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial == nextCertificateSerial {
		t.Fatal("The serials are equal")
	}
}

func (e *testEnv) PreventReissuanceLocalCNwithNoCNandThreeSANDNS(t *testing.T, data testData, config venafiConfigString) {

	randString := e.TestRandString
	domain := "vfidev.com"
	commonName := randString + "." + domain
	data.cn = ""
	data.dnsNS = "alt-" + commonName + "," + "alt2-" + commonName + "," + "alt3" + commonName
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, data)
	e.IssueCertificateAndSaveSerial(t, data, config)
	currentCertificateSerial := e.CertificateSerial
	e.IssueCertificateAndSaveSerial(t, data, config)
	nextCertificateSerial := e.CertificateSerial
	if currentCertificateSerial != nextCertificateSerial {
		t.Fatal("The serials are different")
	}
}

func (e *testEnv) TPPnegativeIssueCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigToken

	e.writeNegativeTPPvenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.NegativeIssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) VAASnegativeIssueCertificate(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"

	var config = venafiConfigCloud

	e.writeNegativeVAASvenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.NegativeIssueCertificateAndSaveSerial(t, data, config)

}

func (e *testEnv) TPPnegativeIssueCertificateParallelism(t *testing.T, data *testData, config venafiConfigString, randString *string) {

	domain := "venafi.example.com"
	if randString != nil {
		data.cn = *randString + "." + domain
	} else {
		data.cn = e.TestRandString + "." + domain
	}
	data.dnsNS = "alt-" + data.cn
	data.dnsIP = "192.168.1.1"
	data.dnsEmail = "venafi@example.com"
	data.storeBy = "hash"

	e.writeNegativeTPPvenafiToBackend(t, config)
	e.writeRoleToBackend(t, config)
	e.NegativeIssueCertificateAndSaveSerial(t, *data, config)

}

func (e *testEnv) writeNegativeTPPvenafiToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)
	roleData["access_token"] = "sdsdsd" // bad input to trigger error on issue

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create venafi, %#v", resp)
	}
}

func (e *testEnv) writeNegativeVAASvenafiToBackend(t *testing.T, configString venafiConfigString) {
	roleData, err := makeConfig(configString)
	if err != nil {
		t.Fatal(err)
	}
	roleData = util.CopyMap(roleData)
	roleData["CLOUD_APIKEY"] = "sdsdsd" // bad input to trigger error on issue

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "venafi/" + e.VenafiSecretName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create venafi, %#v", resp)
	}
}

func (e *testEnv) SetupParallelismEnv(t *testing.T, data *testData, config venafiConfigString, randString *string) {
	domain := "vfidev.com"
	if randString != nil {
		data.cn = *randString + "." + domain
	} else {
		data.cn = e.TestRandString
	}
	commonName := data.cn
	data.dnsNS = "maria-" + commonName + "," + "rose-" + commonName + "," + "bob-" + commonName + "," + "bob-" + commonName + "," + "shina-" + commonName
	data.storeBy = "hash"
	data.storePkey = true

	e.writeVenafiToBackend(t, config)
	e.writeRoleToBackendWithData(t, config, *data)

}

func (e *testEnv) NegativeIssueCertificateAndSaveSerial(t *testing.T, data testData, configString venafiConfigString) {

	var issueData map[string]interface{}

	var altNames []string

	if data.dnsNS != "" {
		altNames = append(altNames, data.dnsNS)
	}
	if data.dnsEmail != "" {
		altNames = append(altNames, data.dnsEmail)
	}
	if data.dnsIP != "" {
		altNames = append(altNames, data.dnsIP)
	}

	if data.keyPassword != "" {
		issueData = map[string]interface{}{
			"common_name":        data.cn,
			"alt_names":          strings.Join(altNames, ","),
			"ip_sans":            []string{data.onlyIP},
			"key_password":       data.keyPassword,
			"private_key_format": "der",
		}
	} else {
		issueData = map[string]interface{}{
			"common_name":        data.cn,
			"alt_names":          strings.Join(altNames, ","),
			"ip_sans":            []string{data.onlyIP},
			"private_key_format": "der",
		}
	}

	if data.privateKeyFormat != "" {
		issueData["private_key_format"] = data.privateKeyFormat
	}

	if data.customFields != nil {
		issueData["custom_fields"] = strings.Join(data.customFields, ",")
	}

	resp, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/" + e.RoleName,
		Storage:   e.Storage,
		Data:      issueData,
	})

	if err == nil && resp != nil {
		t.Fatal("should have returned error and a nil logical response since credentials are wrong")
	}
}

func randSeq(n int) string {
	rand.Seed(time.Now().UTC().UnixNano())
	var letters = []rune("abcdefghijklmnopqrstuvwxyz1234567890")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}
