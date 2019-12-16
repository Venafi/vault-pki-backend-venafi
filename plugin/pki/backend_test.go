package pki

import (
	r "crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"log"
	"os"
	"strings"
	"testing"
)

var (
	stepCount               = 0
	serialUnderTest         string
	parsedKeyUsageUnderTest int
)

type testData struct {
	cert        string
	private_key string
	wrong_cert  string
	wrong_pkey  string
	cn          string
	dns_ns      string
	dns_ip      string
	dns_email   string
	provider    string
	signCSR     bool
	csrPK       []byte
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
	if data.provider == "tpp" {
		wantDNSNames := []string{data.cn, data.dns_ns, data.dns_ip}
		haveDNSNames := parsedCertificate.DNSNames
		if !SameStringSlice(haveDNSNames, wantDNSNames) {
			t.Fatalf("Certificate Subject Alternative Names %s doesn't match to requested %s", haveDNSNames, wantDNSNames)
		}
		if len(parsedCertificate.IPAddresses) != 1 || parsedCertificate.IPAddresses[0].String() != data.dns_ip {
			t.Fatalf("Certificate IPs %v doesn`t match requested %v", parsedCertificate.IPAddresses, data.dns_ip)
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

func TestPKI_Fake_BaseEnroll(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"fakemode":       true,
	})
	if err != nil {
		t.Fatalf("Error configuring role: %s", err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": data.cn,
		"alt_names":   fmt.Sprintf("%s,%s,%s", data.dns_ns, data.dns_ip, data.dns_email),
	})
	if err != nil {
		t.Fatalf("Error issuing certificate: %s", err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("Expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)

	checkStandartCert(t, data)
}

func TestPKI_TPP_BaseEnroll(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"
	data.provider = "tpp"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease":    true,
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": data.cn,
		"alt_names":   fmt.Sprintf("%s,%s,%s", data.dns_ns, data.dns_ip, data.dns_email),
	})
	if err != nil {
		t.Fatal(err)
	}

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)

	checkStandartCert(t, data)
}

func TestPKI_TPP_RestrictedEnroll(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.dns_email = "venafi@example.com"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease":    true,
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPZONE_RESTRICTED"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
		//"service_generated_cert": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": data.cn,
		"alt_names":   fmt.Sprintf("%s,%s,%s", data.dns_ns, data.dns_ip, data.dns_email),
	})
	if err != nil {
		t.Fatal(err)
	}

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)

	checkStandartCert(t, data)
}

func TestPKI_TPP_CSRSign(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.signCSR = true
	data.provider = "tpp"

	var err error
	//Generating CSR for test
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = data.cn
	certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dns_ns)
	org := os.Getenv("CERT_O")
	if org != "" {
		certificateRequest.Subject.Organization = append(certificateRequest.Subject.Organization, org)
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

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease":    true,
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
		//"service_generated_cert": true,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/sign/example", map[string]interface{}{
		"csr": pemCSR,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)

	checkStandartCert(t, data)
}

func TestPKI_Cloud_BaseEnroll(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.provider = "cloud"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"cloud_url":      os.Getenv("CLOUDURL"),
		"zone":           os.Getenv("CLOUDZONE"),
		"apikey":         os.Getenv("CLOUDAPIKEY"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": data.cn,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)

	checkStandartCert(t, data)
}

func TestPKI_Cloud_CSRSign(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.signCSR = true
	data.provider = "cloud"

	var err error
	//Generating CSR for test
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = data.cn
	certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dns_ns)

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

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"cloud_url":      os.Getenv("CLOUDURL"),
		"zone":           os.Getenv("CLOUDZONE"),
		"apikey":         os.Getenv("CLOUDAPIKEY"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/sign/example", map[string]interface{}{
		"csr": pemCSR,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)

	checkStandartCert(t, data)
}

//TODO: have to add support of populating field in Cloud vcert ednpoint
func DoNotRun_Cloud_RestrictedEnroll(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "vfidev.com"
	data.cn = rand + "." + domain
	data.provider = "cloud"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"cloud_url":      os.Getenv("CLOUDURL"),
		"zone":           os.Getenv("CLOUDZONE_RESTRICTED"),
		"apikey":         os.Getenv("CLOUDAPIKEY"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": data.cn,
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)

	checkStandartCert(t, data)
}
