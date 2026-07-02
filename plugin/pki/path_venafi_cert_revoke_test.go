package pki

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" // #nosec G505
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

func TestGetRevokeCertificateIDAcceptsSerialNumber(t *testing.T) {
	schema := pathVenafiCertRevoke(&backend{}).Fields
	role := &roleEntry{StoreBy: util.StoreBySerialString}

	data := &framework.FieldData{
		Schema: schema,
		Raw: map[string]interface{}{
			"serial_number": "AA:BB:CC",
		},
	}
	id := getRevokeCertificateID(data, role)
	if id != "aa-bb-cc" {
		t.Fatalf("expected normalized serial_number, got %q", id)
	}

	data = &framework.FieldData{
		Schema: schema,
		Raw: map[string]interface{}{
			"certificate_uid": "DD:EE:FF",
		},
	}
	id = getRevokeCertificateID(data, role)
	if id != "dd-ee-ff" {
		t.Fatalf("expected compatible normalized certificate_uid, got %q", id)
	}
}

func TestVenafiCertRevokeUnknownIdentifierReturnsLogicalError(t *testing.T) {
	env, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	role := roleEntry{
		StoreBy:      util.StoreBySerialString,
		VenafiSecret: env.VenafiSecretName,
	}
	entry, err := logical.StorageEntryJSON("role/"+env.RoleName, role)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Storage.Put(env.Context, entry); err != nil {
		t.Fatal(err)
	}

	resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "revoke/" + env.RoleName,
		Storage:   env.Storage,
		Data: map[string]interface{}{
			"serial_number": "AA:BB:CC",
		},
	})
	if err != nil {
		t.Fatalf("expected clean logical error response, got Go error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected logical error response, got %#v", resp)
	}
}

func TestVenafiCertRevokeMissingIdentifierReturnsLogicalError(t *testing.T) {
	env, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	role := roleEntry{
		StoreBy:      util.StoreBySerialString,
		VenafiSecret: env.VenafiSecretName,
	}
	entry, err := logical.StorageEntryJSON("role/"+env.RoleName, role)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Storage.Put(env.Context, entry); err != nil {
		t.Fatal(err)
	}

	resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.UpdateOperation,
		Path:      "revoke/" + env.RoleName,
		Storage:   env.Storage,
	})
	if err != nil {
		t.Fatalf("expected clean logical error response, got Go error: %v", err)
	}
	if resp == nil || !resp.IsError() {
		t.Fatalf("expected logical error response, got %#v", resp)
	}
}

func TestGetRevocationRequestCloudUsesStoredCertificateThumbprint(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		t.Fatal(err)
	}

	certPEM, rawCert := testCertificatePEM(t)
	entry, err := logical.StorageEntryJSON("certs/aa-bb-cc", VenafiCert{
		Certificate:  certPEM,
		SerialNumber: "aa:bb:cc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	connector := &revokeTestConnector{connectorType: endpoint.ConnectorTypeCloud}
	var cl endpoint.Connector = connector
	req := &logical.Request{Storage: storage}
	role := &roleEntry{StoreBy: util.StoreBySerialString}

	revReq, err := getRevocationRequest(b, &cl, ctx, req, "", "aa-bb-cc", role)
	if err != nil {
		t.Fatal(err)
	}

	if connector.searchCalled {
		t.Fatal("Cloud revocation should not call SearchCertificates")
	}
	if revReq.CertificateDN != "" {
		t.Fatalf("expected no CertificateDN for Cloud revocation, got %q", revReq.CertificateDN)
	}

	thumbprint := sha1.Sum(rawCert)
	expectedThumbprint := strings.ToUpper(hex.EncodeToString(thumbprint[:]))
	if revReq.Thumbprint != expectedThumbprint {
		t.Fatalf("expected thumbprint %q, got %q", expectedThumbprint, revReq.Thumbprint)
	}
}

func TestGetRevocationRequestNGTSUsesStoredCertificateThumbprint(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		t.Fatal(err)
	}

	certPEM, rawCert := testCertificatePEM(t)
	entry, err := logical.StorageEntryJSON("certs/aa-bb-cc", VenafiCert{
		Certificate:  certPEM,
		SerialNumber: "aa:bb:cc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	connector := &revokeTestConnector{connectorType: endpoint.ConnectorTypeNGTS}
	var cl endpoint.Connector = connector
	req := &logical.Request{Storage: storage}
	role := &roleEntry{StoreBy: util.StoreBySerialString}

	revReq, err := getRevocationRequest(b, &cl, ctx, req, "", "aa-bb-cc", role)
	if err != nil {
		t.Fatal(err)
	}

	if connector.searchCalled {
		t.Fatal("NGTS revocation should not call SearchCertificates")
	}
	if revReq.CertificateDN != "" {
		t.Fatalf("expected no CertificateDN for NGTS revocation, got %q", revReq.CertificateDN)
	}

	thumbprint := sha1.Sum(rawCert)
	expectedThumbprint := strings.ToUpper(hex.EncodeToString(thumbprint[:]))
	if revReq.Thumbprint != expectedThumbprint {
		t.Fatalf("expected thumbprint %q, got %q", expectedThumbprint, revReq.Thumbprint)
	}
}

func testCertificatePEM(t *testing.T) (string, []byte) {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			CommonName: "revoke-test.example.com",
		},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}

	block := &pem.Block{Type: "CERTIFICATE", Bytes: der}
	return string(pem.EncodeToMemory(block)), der
}

type revokeTestConnector struct {
	endpoint.Connector
	connectorType endpoint.ConnectorType
	searchCalled  bool
}

func (c *revokeTestConnector) GetType() endpoint.ConnectorType {
	return c.connectorType
}

func (c *revokeTestConnector) SearchCertificates(_ *certificate.SearchRequest) (*certificate.CertSearchResponse, error) {
	c.searchCalled = true
	return nil, nil
}

var _ endpoint.Connector = (*revokeTestConnector)(nil)
