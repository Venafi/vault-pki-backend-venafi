package pki

import (
	"errors"
	"testing"

	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki/vpkierror"
)

func TestPathVenafiCertDeleteDeletesStoredCertificate(t *testing.T) {
	env, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	certID := "stale.example.com"
	entry, err := logical.StorageEntryJSON("certs/"+certID, VenafiCert{
		Certificate:      "certificate",
		CertificateChain: "certificate-chain",
		SerialNumber:     "aa:bb:cc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Storage.Put(env.Context, entry); err != nil {
		t.Fatal(err)
	}

	resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cert/" + certID,
		Storage:   env.Storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp == nil || resp.IsError() {
		t.Fatalf("expected stored certificate to be readable before delete, got %#v", resp)
	}

	resp, err = env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "cert/" + certID,
		Storage:   env.Storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("delete returned logical error: %#v", resp)
	}

	_, err = env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.ReadOperation,
		Path:      "cert/" + certID,
		Storage:   env.Storage,
	})
	if err == nil {
		t.Fatal("expected missing certificate error after delete")
	}
	if !errors.As(err, &vpkierror.CertEntryNotFound{}) {
		t.Fatalf("expected CertEntryNotFound after delete, got %T: %v", err, err)
	}
}

func TestPathVenafiCertDeleteDoesNotRequireRoleOrVenafiSecret(t *testing.T) {
	env, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "cert/missing.example.com",
		Storage:   env.Storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("delete returned logical error: %#v", resp)
	}
}

func TestPathVenafiCertDeleteSupportsWildcardCommonName(t *testing.T) {
	env, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	certID := "*.example.com"
	entry, err := logical.StorageEntryJSON("certs/"+certID, VenafiCert{
		Certificate:      "certificate",
		CertificateChain: "certificate-chain",
		SerialNumber:     "aa:bb:cc",
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := env.Storage.Put(env.Context, entry); err != nil {
		t.Fatal(err)
	}

	resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "cert/" + certID,
		Storage:   env.Storage,
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp != nil && resp.IsError() {
		t.Fatalf("delete returned logical error: %#v", resp)
	}

	entry, err = env.Storage.Get(env.Context, "certs/"+certID)
	if err != nil {
		t.Fatal(err)
	}
	if entry != nil {
		t.Fatalf("expected wildcard certificate %q to be deleted", certID)
	}
}

func TestPathVenafiCertDeleteRejectsNestedCertificateUID(t *testing.T) {
	env, err := NewIntegrationTestEnv()
	if err != nil {
		t.Fatal(err)
	}

	resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
		Operation: logical.DeleteOperation,
		Path:      "cert/example.com/metadata",
		Storage:   env.Storage,
	})
	if err != logical.ErrUnsupportedPath {
		t.Fatalf("expected unsupported path error, got response=%#v error=%v", resp, err)
	}
}

func TestPathVenafiCertDeleteRouteMatchesExpectedCertificateUIDs(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr error
	}{
		{
			name: "common name",
			path: "cert/example.com",
		},
		{
			name: "wildcard common name",
			path: "cert/*.example.com",
		},
		{
			name: "normalized serial",
			path: "cert/aa-bb-cc",
		},
		{
			name: "hash",
			path: "cert/0123456789abcdef",
		},
		{
			name:    "empty uid",
			path:    "cert/",
			wantErr: logical.ErrUnsupportedPath,
		},
		{
			name:    "nested uid",
			path:    "cert/example.com/metadata",
			wantErr: logical.ErrUnsupportedPath,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env, err := NewIntegrationTestEnv()
			if err != nil {
				t.Fatal(err)
			}

			resp, err := env.Backend.HandleRequest(env.Context, &logical.Request{
				Operation: logical.DeleteOperation,
				Path:      tt.path,
				Storage:   env.Storage,
			})
			if err != tt.wantErr {
				t.Fatalf("expected error %v, got response=%#v error=%v", tt.wantErr, resp, err)
			}
			if tt.wantErr == nil && resp != nil && resp.IsError() {
				t.Fatalf("delete returned logical error: %#v", resp)
			}
		})
	}
}
