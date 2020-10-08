package pki

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathVenafiFetchListCerts(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "certs/?$",

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ListOperation: b.pathVenafiFetchCertList,
		},

		HelpSynopsis:    pathVenafiFetchHelpSyn,
		HelpDescription: pathVenafiFetchHelpDesc,
	}
}

func (b *backend) pathVenafiFetchCertList(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	entries, err := req.Storage.List(ctx, "certs/")
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

const pathVenafiFetchHelpSyn = `
This allows certificates to be fetched.
`

const pathVenafiFetchHelpDesc = `
This allows certificates to be fetched.
`
