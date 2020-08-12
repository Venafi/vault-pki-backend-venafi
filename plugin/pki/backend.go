package pki

import (
	"context"
	"github.com/hashicorp/vault/sdk/logical"
	"github.com/hashicorp/vault/sdk/framework"
	"strings"
)

// Factory creates a new backend implementing the logical.Backend interface
func Factory(ctx context.Context, conf *logical.BackendConfig) (logical.Backend, error) {
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		return nil, err
	}
	return b, nil
}

// Backend returns a new Backend framework struct
func Backend(conf *logical.BackendConfig) *backend {
	var b backend
	b.Backend = &framework.Backend{
		Help: strings.TrimSpace(backendHelp),

		PathsSpecial: &logical.Paths{
			SealWrapStorage: []string{
				"roles/",
			},
		},

		Paths: []*framework.Path{
			pathListRoles(&b),
			pathRoles(&b),
			pathVenafiCertEnroll(&b),
			pathVenafiCertSign(&b),
			pathVenafiCertRead(&b),
			pathVenafiCertRevoke(&b),
			pathVenafiFetchListCerts(&b),
		},

		Secrets: []*framework.Secret{
			secretCerts(&b),
		},

		BackendType: logical.TypeLogical,
	}
	b.storage = conf.StorageView
	return &b
}

type backend struct {
	*framework.Backend
	storage logical.Storage
}

const (
	backendHelp = `
The Venafi certificates backend plugin requests certificates from TPP of Condor.

After mounting this backend create a role using role/ path.
`
	utilityName = "HashiCorp Vault"
)
