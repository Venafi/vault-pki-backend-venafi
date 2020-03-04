package pki

import (
	"context"
	r "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"log"
	"net"
	"os"
	"strings"
	"testing"
	"time"
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
	cert      string
	cn        string
	csrPK     []byte
	dns_email string
	//dns_ip added to alt_names to support some old browsers which can't parse IP Addresses x509 extension
	dns_ip string
	dns_ns string
	//only_ip added IP Address x509 field
	only_ip     string
	keyPassword string
	private_key string
	provider    venafiConfigString
	signCSR     bool
}

const (
	venafiConfigTPP             venafiConfigString = "TPP"
	venafiConfigTPPRestricted   venafiConfigString = "TPPRestricted"
	venafiConfigCloud           venafiConfigString = "Cloud"
	venafiConfigCloudRestricted venafiConfigString = "CloudRestricted"
	venafiConfigFake            venafiConfigString = "Fake"
)

var venafiTestTPPConfig = map[string]interface{}{
	"tpp_url":           os.Getenv("TPPURL"),
	"tpp_user":          os.Getenv("TPPUSER"),
	"tpp_password":      os.Getenv("TPPPASSWORD"),
	"zone":              os.Getenv("TPPZONE"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestTPPConfigRestricted = map[string]interface{}{
	"tpp_url":           os.Getenv("TPPURL"),
	"tpp_user":          os.Getenv("TPPUSER"),
	"tpp_password":      os.Getenv("TPPPASSWORD"),
	"zone":              os.Getenv("TPPZONE_RESTRICTED"),
	"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
}

var venafiTestCloudConfig = map[string]interface{}{
	"cloud_url": os.Getenv("CLOUDURL"),
	"apikey":    os.Getenv("CLOUDAPIKEY"),
	"zone":      os.Getenv("CLOUDZONE"),
}

var venafiTestCloudConfigRestricted = map[string]interface{}{
	"cloud_url": os.Getenv("CLOUDURL"),
	"apikey":    os.Getenv("CLOUDAPIKEY"),
	"zone":      os.Getenv("CLOUDRESTRICTEDZONE"),
}

var venafiTestFakeConfig = map[string]interface{}{
	"generate_lease":  true,
	"fakemode":        true,
	"store_by_cn":     true,
	"store_by_serial": true,
	"store_pkey":      true,
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

	if !sliceContains(resp.Data["keys"].([]string), e.RoleName) {
		t.Fatalf("expected role name %s in list %s", e.RoleName, resp.Data["keys"])
	}
}

func (e *testEnv) IssueCertificate(t *testing.T, data testData, configString venafiConfigString) {

	var issueData map[string]interface{}

	var altNames string

	if data.dns_ip != "" {
		altNames = fmt.Sprintf("%s,%s, %s", data.dns_ns, data.dns_email, data.dns_ip)
	} else {
		altNames = fmt.Sprintf("%s,%s", data.dns_ns, data.dns_email)
	}

	if data.keyPassword != "" {
		issueData = map[string]interface{}{
			"common_name":  data.cn,
			"alt_names":    altNames,
			"ip_sans":      []string{data.only_ip},
			"key_password": data.keyPassword,
		}
	} else {
		issueData = map[string]interface{}{
			"common_name": data.cn,
			"alt_names":   altNames,
			"ip_sans":     []string{data.only_ip},
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
		data.private_key = string(pem.EncodeToMemory(b))
	} else {
		data.private_key = resp.Data["private_key"].(string)
	}

	data.provider = configString

	checkStandartCert(t, data)

	resp, err = e.Backend.HandleRequest(e.Context, &logical.Request{
		Operation: logical.ListOperation,
		Path:      "certs",
		Storage:   e.Storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println(resp)
}

func (e *testEnv) SignCertificate(t *testing.T, data testData, configString venafiConfigString) {

	//Generating CSR for test
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = data.cn
	if data.dns_ns != "" {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dns_ns)
	}

	if data.dns_ip != "" {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dns_ip)
	}

	if configString == venafiConfigFake {
		certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.cn)
	}

	if data.only_ip != "" {
		certificateRequest.IPAddresses = []net.IP{net.ParseIP(data.only_ip)}
	}

	if data.dns_ip != "" {
		certificateRequest.IPAddresses = append(certificateRequest.IPAddresses, net.ParseIP(data.dns_ip))
	}

	if data.dns_email != "" {
		certificateRequest.EmailAddresses = []string{data.dns_email}
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
		t.Fatalf("failed to issue certificate, %#v", resp.Data["error"])
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
	data.private_key = resp.Data["private_key"].(string)
	checkStandartCert(t, data)

	//Set certificate serial number for FakeReadCertificateBySerial test
	e.CertificateSerial = resp.Data["serial_number"].(string)
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

	if !sliceContains(resp.Data["keys"].([]string), data.cn) {
		t.Fatalf("expected CN %s in list %s", data.cn, resp.Data["keys"])
	}
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

	if err == nil {
		t.Fatalf("revoke path is not implemented yet and should return error")
	}
	if err.Error() != "not implemented yet" {
		t.Fatalf("error message should be not implemented yet not %s", err)
	}

}

func makeConfig(configString venafiConfigString) (roleData map[string]interface{}, err error) {

	switch configString {
	case venafiConfigFake:
		roleData = venafiTestFakeConfig
	case venafiConfigTPP:
		roleData = venafiTestTPPConfig
	case venafiConfigTPPRestricted:
		roleData = venafiTestTPPConfigRestricted
	case venafiConfigCloud:
		roleData = venafiTestCloudConfig
	case venafiConfigCloudRestricted:
		roleData = venafiTestCloudConfigRestricted
	default:
		return roleData, fmt.Errorf("Don't have config data for config %s", configString)
	}

	return roleData, nil

}

func (e *testEnv) FakeCreateRole(t *testing.T) {

	var config = venafiConfigFake
	e.writeRoleToBackend(t, config)

}

func (e *testEnv) FakeListRole(t *testing.T) {
	e.listRolesInBackend(t)

}

func (e *testEnv) FakeIssueCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigFake
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) FakeReadCertificateByCN(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigFake
	e.ReadCertificate(t, data, config, data.cn)

}

func (e *testEnv) FakeReadCertificateBySerial(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigFake
	e.ReadCertificate(t, data, config, normalizeSerial(e.CertificateSerial))

}

func (e *testEnv) FakeRevokeCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	e.RevokeCertificate(t, data.cn)

}

func (e *testEnv) FakeListCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigFake
	e.ListCertificates(t, data, config)

}

func (e *testEnv) FakeIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigFake

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) FakeIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"
	data.keyPassword = "password"

	var config = venafiConfigFake

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) FakeSignCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "-signed." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"
	data.keyPassword = "password"
	data.signCSR = true

	var config = venafiConfigFake

	e.SignCertificate(t, data, config)
}

func (e *testEnv) TPPIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigTPP

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) TPPIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.keyPassword = "Pass0rd!"

	var config = venafiConfigTPP

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) TPPIntegrationIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.only_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigTPPRestricted

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) TPPIntegrationSignCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "127.0.0.1"
	data.only_ip = "192.168.0.1"
	data.signCSR = true

	var config = venafiConfigTPP

	e.writeRoleToBackend(t, config)
	e.SignCertificate(t, data, config)

}

func (e *testEnv) CloudIntegrationSignCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.signCSR = true

	var config = venafiConfigCloud

	e.writeRoleToBackend(t, config)
	e.SignCertificate(t, data, config)

}

func (e *testEnv) CloudIntegrationIssueCertificate(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "venafi.example.com"
	data.cn = rand + "." + domain

	var config = venafiConfigCloud

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)
}

func (e *testEnv) CloudIntegrationIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "vfidev.com"
	data.cn = rand + "." + domain

	var config = venafiConfigCloud

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)
}

func (e *testEnv) CloudIntegrationIssueCertificateWithPassword(t *testing.T) {

	data := testData{}
	rand := e.TestRandString
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.keyPassword = "password"

	var config = venafiConfigCloud

	e.writeRoleToBackend(t, config)
	e.IssueCertificate(t, data, config)
}

func checkStandartCert(t *testing.T, data testData) {
	var err error
	log.Println("Testing certificate:", data.cert)
	certPEMBlock, _ := pem.Decode([]byte(data.cert))
	if certPEMBlock == nil {
		t.Fatalf("Certificate data is nil in the pem block")
	}

	if !data.signCSR {
		log.Println("Testing private key:", data.private_key)
		keyPEMBlock, _ := pem.Decode([]byte(data.private_key))
		if keyPEMBlock == nil {
			t.Fatalf("Private key data is nil in thew private key")
		}
		_, err = tls.X509KeyPair([]byte(data.cert), []byte(data.private_key))
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

	wantDNSNames := []string{data.cn, data.dns_ns}

	if data.dns_ip != "" {
		wantDNSNames = append(wantDNSNames, data.dns_ip)
	}

	ips := make([]net.IP, 0, 2)
	if data.only_ip != "" {
		ips = append(ips, net.ParseIP(data.only_ip))
	}
	if data.dns_ip != "" {
		ips = append(ips, net.ParseIP(data.dns_ip))
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

	if data.dns_email != "" {
		wantEmail := []string{data.dns_email}
		if !SameStringSlice(parsedCertificate.EmailAddresses, wantEmail) {
			t.Fatalf("Certificate emails %v doesn't match requested %v", parsedCertificate.EmailAddresses, wantEmail)
		}
	}

}
func newIntegrationTestEnv() (*testEnv, error) {
	ctx := context.Background()
	//defaultLeaseTTLVal := time.Hour * 24
	//maxLeaseTTLVal := time.Hour * 24 * 32
	//
	//b, err := Factory(context.Background(), &logical.BackendConfig{
	//	Logger: nil,
	//	System: &logical.StaticSystemView{
	//		DefaultLeaseTTLVal: defaultLeaseTTLVal,
	//		MaxLeaseTTLVal:     maxLeaseTTLVal,
	//	},
	//})
	//if err != nil {
	//	return nil, err
	//}

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
