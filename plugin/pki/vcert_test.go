package pki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"
	"log"
	"strings"
	"testing"
)

func TestPKIVcertIsWorking(t *testing.T) {
	var err error

	const cn = "testfake.example.com"
	vencfg := &vcert.Config{ConnectorType: endpoint.ConnectorTypeFake}
	client, err := vcert.NewClient(vencfg)

	req := &certificate.Request{}

	req.DNSNames = []string{cn}

	fmt.Printf("%v\n", req.DNSNames)
	req.Subject.CommonName = cn

	reader := rand.Reader
	bitSize := 2048

	key, err := rsa.GenerateKey(reader, bitSize)
	req.PrivateKey = key

	certificateRequest := x509.CertificateRequest{}
	certificateRequest.Subject = req.Subject
	certificateRequest.DNSNames = req.DNSNames
	certificateRequest.EmailAddresses = req.EmailAddresses
	certificateRequest.IPAddresses = req.IPAddresses
	certificateRequest.Attributes = req.Attributes

	csr, err := x509.CreateCertificateRequest(rand.Reader, &certificateRequest, key)
	if err != nil {
		t.Fatalf("bad: err: %v resp: %#v", err, nil)
	}
	err = req.SetCSR(csr)
	if err != nil {
		t.Fatalf("bad: err: %v \n", err)
	}

	pickupId, err := client.RequestCertificate(req)
	if err != nil {
		t.Fatalf("bad: err: %v resp: %#v", err, nil)
	}
	var cert *certificate.PEMCollection

	cert, err = client.RetrieveCertificate(&certificate.Request{PickupID: pickupId})
	if err != nil {
		t.Fatal(err)
	}

	crt := strings.Join([]string{cert.Certificate}, "\n")
	pemBlock, _ := pem.Decode([]byte(crt))
	parsedCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	haveCN := parsedCertificate.Subject.CommonName
	log.Println("CN is", haveCN)
	if haveCN != cn {
		t.Fatalf("CommonName doesn't match %s.", cn)
	}
}

func TestPKIVcertConfig(t *testing.T) {
	var resp *logical.Response
	var err error
	b, storage := createBackendWithStorage(t)

	roleData := map[string]interface{}{
		"fakemode":        "true",
		"ttl":             "1h",
		"generate_lease":  "true",
		"store_by_cn":     "true",
		"store_pkey":      "true",
		"store_by_serial": "true",
		"venafi_secret":   "venafi",
		"zone":            "fakeZone",
	}

	roleReq := &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "roles/testrole",
		Storage:   storage,
		Data:      roleData,
	}

	resp, err = b.HandleRequest(context.Background(), roleReq)
	if err != nil || (resp != nil && resp.IsError()) {
		t.Fatalf("bad: err: %v resp: %#v", err, resp)
	}

}

func createBackendWithStorage(t *testing.T) (*backend, logical.Storage) {
	config := logical.TestBackendConfig()
	config.StorageView = &logical.InmemStorage{}

	var err error
	b := Backend(config)
	err = b.Setup(context.Background(), config)
	if err != nil {
		t.Fatal(err)
	}
	return b, config.StorageView
}
