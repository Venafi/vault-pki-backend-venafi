package pki

import (
	"context"
	"fmt"

	"github.com/hashicorp/vault/helper/errutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
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

func fetchCertBySerial(ctx context.Context, req *logical.Request, prefix, serial string) (*logical.StorageEntry, error) {
	var path string
	var err error
	var certEntry *logical.StorageEntry

	hyphenSerial := normalizeSerial(serial)
	path = "certs/" + hyphenSerial

	certEntry, err = req.Storage.Get(ctx, path)
	if err != nil {
		return nil, errutil.InternalError{Err: fmt.Sprintf("error fetching certificate %s: %s", serial, err)}
	}
	if certEntry != nil {
		if certEntry.Value == nil || len(certEntry.Value) == 0 {
			return nil, errutil.InternalError{Err: fmt.Sprintf("returned certificate bytes for serial %s were empty", serial)}
		}
		return certEntry, nil
	}
	return certEntry, nil
}

const pathVenafiFetchHelpSyn = `
This allows certificates to be fetched.
`

const pathVenafiFetchHelpDesc = `
This allows certificates to be fetched.
`
