package pki

import (
	"context"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathVenafiCertRevoke(b *backend) *framework.Path {
	return &framework.Path{
		//Pattern: "certs/(?P<certificate_uid>[0-9a-z-.]+)",
		Pattern: "cert/" + framework.GenericNameRegex("certificate_uid"),
		Fields: map[string]*framework.FieldSchema{
			"certificate_uid": {
				Type:        framework.TypeString,
				Description: "Common name for created certificate",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.venafiCertRevoke,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) venafiCertRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	//TODO: Add revoke function here

	return nil, nil
}
