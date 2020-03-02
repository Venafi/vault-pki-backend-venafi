package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

type testEnv struct {
	Backend logical.Backend
	Context context.Context
	Storage logical.Storage
}

type venafiConfigString string

type testData struct {
	cert        string
	private_key string
	wrong_cert  string
	wrong_pkey  string
	cn          string
	dns_ns      string
	dns_ip      string
	only_ip     string
	dns_email   string
	provider    venafiConfigString
	signCSR     bool
	csrPK       []byte
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
	"generate_lease": true,
	"fakemode":       true,
}

func (e *testEnv) IssueCertificate(t *testing.T, data testData, config venafiConfigString) {

	var roleData map[string]interface{}
	var roleName string

	switch config {
	case venafiConfigFake:
		roleData = venafiTestFakeConfig
		roleName = "fake-role"
	case venafiConfigTPP:
		roleData = venafiTestTPPConfig
		roleName = "tpp-role"
	case venafiConfigTPPRestricted:
		roleData = venafiTestTPPConfigRestricted
		roleName = "tpp-role-restricted"
	case venafiConfigCloud:
		roleData = venafiTestCloudConfig
		roleName = "cloud-role"
	case venafiConfigCloudRestricted:
		roleData = venafiTestCloudConfigRestricted
		roleName = "cloud-role-restricted"
	default:
		t.Fatalf("Don't have config data for config %s", config)
	}

	resp, err := e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/" + roleName,
		Storage:   e.Storage,
		Data:      roleData,
	})

	if err != nil {
		t.Fatal(err)
	}

	if resp != nil && resp.IsError() {
		t.Fatalf("failed to create role, %#v", resp)
	}

	resp, err = e.Backend.HandleRequest(context.Background(), &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "issue/" + roleName,
		Storage:   e.Storage,
		Data: map[string]interface{}{
			"common_name": data.cn,
			"alt_names":   fmt.Sprintf("%s,%s,%s", data.dns_ns, data.dns_ip, data.dns_email),
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

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)
	data.provider = config

	checkStandartCert(t, data)
}

func (e *testEnv) FakeIssueCertificate(t *testing.T) {

	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigFake
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) TPPIssueCertificate(t *testing.T) {

	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigTPP
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) TPPIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"

	var config = venafiConfigTPPRestricted
	e.IssueCertificate(t, data, config)

}

func (e *testEnv) CloudIssueCertificate(t *testing.T) {

	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain

	var config = venafiConfigCloud
	e.IssueCertificate(t, data, config)
}

func (e *testEnv) CloudIssueCertificateRestricted(t *testing.T) {

	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain

	var config = venafiConfigCloud
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

	//TODO: cloud now have SAN support too. Have to implement it
	if data.provider == venafiConfigTPP {
		wantDNSNames := []string{data.cn, data.dns_ns, data.dns_ip}
		haveDNSNames := parsedCertificate.DNSNames
		ips := make([]net.IP, 0, 2)
		if data.dns_ip != "" {
			ips = append(ips, net.ParseIP(data.dns_ip))
		}
		if data.only_ip != "" {
			ips = append(ips, net.ParseIP(data.only_ip))
		}
		if !SameStringSlice(haveDNSNames, wantDNSNames) {
			t.Fatalf("Certificate Subject Alternative Names %s doesn't match to requested %s", haveDNSNames, wantDNSNames)
		}

		if !SameIpSlice(ips, parsedCertificate.IPAddresses) {
			t.Fatalf("Certificate IPs %v doesn`t match requested %v", parsedCertificate.IPAddresses, ips)
		}
		//TODO: check email too
		//wantEmail := []string{data.dns_email}
		//TODO: in policies branch Cloud endpoint should start to populate O,C,L.. fields too
		wantOrg := os.Getenv("CERT_O")
		if wantOrg != "" {
			var haveOrg string
			if len(parsedCertificate.Subject.Organization) > 0 {
				haveOrg = parsedCertificate.Subject.Organization[0]
			} else {
				t.Fatalf("Organization in certificate is empty.")
			}
			log.Println("want and have", wantOrg, haveOrg)
			if wantOrg != haveOrg {
				t.Fatalf("Certificate Organization %s doesn't match to requested %s", haveOrg, wantOrg)
			}
		}
	}
}

func newIntegrationTestEnv(t *testing.T) (*testEnv, error) {
	ctx := context.Background()
	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 32

	b, err := Factory(context.Background(), &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	})
	if err != nil {
		return nil, err
	}
	return &testEnv{
		Backend: b,
		Context: ctx,
		Storage: &logical.InmemStorage{},
	}, nil
}
