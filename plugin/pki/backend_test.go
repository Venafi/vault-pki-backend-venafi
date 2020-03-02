package pki

import (
	r "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
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
	t.Run("TPP restricted enroll", integrationTestEnv.TPPIssueCertificateRestricted)
	t.Run("TPP sign certificate", integrationTestEnv.TPPSignCertificate)
	t.Run("Cloud base enroll", integrationTestEnv.CloudIssueCertificate)
	t.Run("Cloud restricted enroll", integrationTestEnv.CloudIssueCertificateRestricted)

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
