package pki

import (
	"context"
	r "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"math/rand"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/hashicorp/vault/sdk/logical"
)

type testEnv struct {
	Backend           logical.Backend
	Context           context.Context
	Storage           logical.Storage
	TestRandString    string
	RoleName          string
	CertificateSerial string
}

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
	onlyIP      string
	keyPassword string
	privateKey  string
	provider    venafiConfigString
	signCSR     bool
}

const (
	venafiConfigTPP                         venafiConfigString = "TPP"
	venafiConfigTPPPredefined               venafiConfigString = "TPPPredefined"
	venafiConfigCloudPredefined             venafiConfigString = "CloudPredefined"
	venafiConfigTPPRestricted               venafiConfigString = "TPPRestricted"
	venafiConfigCloud                       venafiConfigString = "Cloud"
	venafiConfigCloudRestricted             venafiConfigString = "CloudRestricted"
	venafiConfigFake                        venafiConfigString = "Fake"
	venafiConfigFakeDeprecatedStoreByCN     venafiConfigString = "FakeDeprecatedStoreByCN"
	venafiConfigFakeDeprecatedStoreBySerial venafiConfigString = "venafiConfigFakeDeprecatedStoreBySerial"
	venafiConfigFakeStoreByCN               venafiConfigString = "venafiConfigFakeStoreByCN"
	venafiConfigFakeStoreBySerial           venafiConfigString = "venafiConfigFakeStoreBySerial"
	venafiConfigFakeNoStore                 venafiConfigString = "venafiConfigFakeNoStore"
	venafiConfigFakeNoStorePKey             venafiConfigString = "venafiConfigFakeNoStorePKey"
	venafiConfigMixed                       venafiConfigString = "Mixed"
)

var venafiTestTPPConfig = map[string]interface{}{
	"tpp_url":           os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestTPPConfigPredefined = map[string]interface{}{
	"tpp_url":           "https://tpp.example.com/vedsdk",
	"tpp_user":          "admin",
	"tpp_password":      "strongPassword",
	"zone":              "devops\\vcert",
	"trust_bundle_file": "/opt/venafi/bundle.pem",
}

var venafiTestTPPConfigRestricted = map[string]interface{}{
	"tpp_url":           os.Getenv("TPP_URL"),
	"tpp_user":          os.Getenv("TPP_USER"),
	"tpp_password":      os.Getenv("TPP_PASSWORD"),
	"zone":              os.Getenv("TPP_ZONE_RESTRICTED"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestCloudConfig = map[string]interface{}{
	"cloud_url": os.Getenv("CLOUD_URL"),
	"apikey":    os.Getenv("CLOUD_APIKEY"),
	"zone":      os.Getenv("CLOUD_ZONE"),
}

var venafiTestCloudConfigPredefined = map[string]interface{}{
	"apikey": "xxxx-xxxxx-xxxxxx-xxxxxx",
	"zone":   "xxxxx-xxxxx-xxxxxx-xxxxxx-xxxx",
}

var venafiTestCloudConfigRestricted = map[string]interface{}{
	"cloud_url": os.Getenv("CLOUD_URL"),
	"apikey":    os.Getenv("CLOUD_APIKEY"),
	"zone":      os.Getenv("CLOUD_ZONE_RESTRICTED"),
}

var venafiTestFakeConfigDeprecatedStoreByCN = map[string]interface{}{
	"generate_lease": true,
	"fakemode":       true,
	"store_by_cn":    true,
	"store_pkey":     true,
}

var venafiTestFakeConfigDeprecatedStoreBySerial = map[string]interface{}{
	"generate_lease":  true,
	"fakemode":        true,
	"store_by_serial": true,
	"store_pkey":      true,
}

var venafiTestFakeConfigStoreByCN = map[string]interface{}{
	"generate_lease": true,
	"fakemode":       true,
	"store_by":       "cn",
	"store_pkey":     true,
}

var venafiTestFakeConfigStoreBySerial = map[string]interface{}{
	"generate_lease": true,
	"fakemode":       true,
	"store_by":       "serial",
	"store_pkey":     true,
}

var venafiTestFakeConfig = map[string]interface{}{
	"generate_lease": true,
	"fakemode":       true,
	"store_pkey":     true,
}

var venafiTestFakeConfigNoStore = map[string]interface{}{
	"generate_lease": true,
	"fakemode":       true,
	"no_store":       true,
}

var venafiTestFakeConfigNoStorePKey = map[string]interface{}{
	"generate_lease": true,
	"fakemode":       true,
	"store_pkey":     false,
}

var venafiTestMixedConfig = map[string]interface{}{
	"apikey":  "xxxxxxxxxxxxxxxx",
	"tpp_url": "xxxxxxxxxxx",
}

func (e *testEnv) writeRoleToBackend(t *testing.T, configString venafiConfigString) {
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

	if errText != errorTextTPPandCloudMixedCredentials {
		t.Fatalf("Expecting error with text %s but got %s", errorTextTPPandCloudMixedCredentials, errText)
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

	if !sliceContains(resp.Data["keys"].([]string), e.RoleName) {
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
		if sliceContains(sensitiveData, k) {
			if resp.Data[k] != nil {
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

	//it is need to determine if we're checking cloud signed certificate in checkStandartCert
	data.provider = configString

	checkStandartCert(t, data)

	//save certificate serial for the next test
	e.CertificateSerial = resp.Data["serial_number"].(string)
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

	checkStandartCert(t, data)
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
	checkStandartCert(t, data)

}

func (e *testEnv) CheckThatThereIsNoCertificate(t *testing.T, certId string) {

	_, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cert/" + certId,
		Storage:   e.Storage,
	})

	if err == nil {
		t.Fatal("should be no entry error if there is no certificate")
	}

	const noCertError = "no entry found in path"
	certContain := strings.Contains(err.Error(), noCertError)
	if !certContain {
		t.Fatalf("error should contain %s substring but it is %s", noCertError, err)
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

	_, err := e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "revoke/" + e.RoleName,
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"certificate_uid": certId,
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
	case venafiConfigTPPRestricted:
		roleData = venafiTestTPPConfigRestricted
	case venafiConfigCloud:
		roleData = venafiTestCloudConfig
	case venafiConfigCloudRestricted:
		roleData = venafiTestCloudConfigRestricted
	case venafiConfigCloudPredefined:
		roleData = venafiTestCloudConfigPredefined
	case venafiConfigMixed:
		roleData = venafiTestMixedConfig
	case venafiConfigTPPPredefined:
		roleData = venafiTestTPPConfigPredefined
	default:
		return roleData, fmt.Errorf("do not have config data for config %s", configString)
	}

	return roleData, nil

}

func (e *testEnv) FakeCreateRole(t *testing.T) {

	var config = venafiConfigFake
	e.writeRoleToBackend(t, config)

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

func (e *testEnv) TPPCreateRole(t *testing.T) {

	var config = venafiConfigTPPPredefined
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) CloudCreateRole(t *testing.T) {

	var config = venafiConfigCloudPredefined
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) CreateMixedRole(t *testing.T) {

	var config = venafiConfigMixed
	e.failToWriteRoleToBackend(t, config)

}

func (e *testEnv) FakeCheckThatThereIsNoCertificate(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain

	e.CheckThatThereIsNoCertificate(t, normalizeSerial(e.CertificateSerial))

}

func (e *testEnv) FakeCheckThatThereIsNoPKey(t *testing.T) {
	data := testData{}
	randString := e.TestRandString
	domain := "venafi.example.com"
	data.cn = randString + "." + domain

	e.CheckThatThereIsNoPKey(t, normalizeSerial(e.CertificateSerial))
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
		t.Fatalf("should be no output on reading the delted role %s, but response is: %#v", e.RoleName, resp)
	}

}

func (e *testEnv) FakeListRole(t *testing.T) {
	e.listRolesInBackend(t)

}

func (e *testEnv) FakeReadRole(t *testing.T) {

	e.readRolesInBackend(t, venafiTestFakeConfig)

}

func (e *testEnv) TPPReadRole(t *testing.T) {

	e.readRolesInBackend(t, venafiTestTPPConfigPredefined)

}

func (e *testEnv) CloudReadRole(t *testing.T) {

	e.readRolesInBackend(t, venafiTestCloudConfigPredefined)

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
	e.ReadCertificate(t, data, config, normalizeSerial(e.CertificateSerial))

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

	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func (e *testEnv) CloudIntegrationIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	randString := e.TestRandString
	domain := "vfidev.com"
	data.cn = randString + "." + domain
	data.dnsNS = "www." + data.cn

	var config = venafiConfigCloud

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

	e.writeRoleToBackend(t, config)
	e.IssueCertificateAndSaveSerial(t, data, config)
}

func checkStandartCert(t *testing.T, data testData) {
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

	wantDNSNames := []string{data.cn, data.dnsNS}

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

	if data.provider == venafiConfigCloud {
		//This is a workaround since in cloud used Vault 1.0 as internal CA which is duplicating DNSNames
		//After test cloud update to Vault > 1.3 we can remove this
		parsedCertificate.DNSNames = unique(parsedCertificate.DNSNames)
	}

	if !SameStringSlice(parsedCertificate.DNSNames, wantDNSNames) {
		t.Fatalf("Certificate Subject Alternative Names %v doesn't match to requested %v", parsedCertificate.DNSNames, wantDNSNames)
	}

	if !SameIpSlice(ips, parsedCertificate.IPAddresses) {
		t.Fatalf("Certificate IPs %v doesn`t match requested %v", parsedCertificate.IPAddresses, ips)
	}

	if data.dnsEmail != "" {
		wantEmail := []string{data.dnsEmail}
		if !SameStringSlice(parsedCertificate.EmailAddresses, wantEmail) {
			t.Fatalf("Certificate emails %v doesn't match requested %v", parsedCertificate.EmailAddresses, wantEmail)
		}
	}

}
func newIntegrationTestEnv() (*testEnv, error) {
	ctx := context.Background()

	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	var err error
	b := Backend(config)
	err = b.Setup(context.Background(), config)
	if err != nil {
		return nil, err
	}

	return &testEnv{
		Backend:        b,
		Context:        ctx,
		Storage:        config.StorageView,
		TestRandString: randSeq(9),
		RoleName:       randSeq(9) + "-role",
	}, nil
}

func unique(intSlice []string) []string {
	keys := make(map[string]bool)
	var list []string
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
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
