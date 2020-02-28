package pki

import (
	r "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"net"
	"os"
	"strings"
	"testing"
)

var (
	stepCount               = 0
	serialUnderTest         string
	parsedKeyUsageUnderTest int
)

func TestIntegration(t *testing.T) {

	integrationTestEnv, err := newIntegrationTestEnv(t)
	if err != nil {
		t.Fatal(err)
	}


	t.Run("fake base enroll", integrationTestEnv.FakeIssueCertificate)
	t.Run("TPP base enroll", integrationTestEnv.TPPIssueCertificate)
	t.Run("Cloud base enroll", integrationTestEnv.CloudIssueCertificate)

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
		Logger: hclog.NewNullLogger(),
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
		Logger: hclog.NewNullLogger(),
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
		"alt_names":   fmt.Sprintf("%s,%s", data.dns_ns, data.dns_email),
		"ip_sans":     []string{data.dns_ip},
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
	data.dns_ip = "127.0.0.1"
	data.signCSR = true
	data.provider = "tpp"

	var err error
	//Generating CSR for test
	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject.CommonName = data.cn
	certificateRequest.DNSNames = append(certificateRequest.DNSNames, data.dns_ns, data.dns_ip)
	certificateRequest.IPAddresses = []net.IP{net.ParseIP(data.dns_ip)}
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
		Logger: hclog.NewNullLogger(),
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
		Logger: hclog.NewNullLogger(),
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
		Logger: hclog.NewNullLogger(),
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
		Logger: hclog.NewNullLogger(),
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
