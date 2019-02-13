package pki

import (
	"context"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/hashicorp/vault/helper/errutil"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
)

func pathVenafiFetchValid(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `cert/(?P<serial>[0-9A-Fa-f-:]+)`,
		Fields: map[string]*framework.FieldSchema{
			"serial": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `Certificate serial number, in colon- or
hyphen-separated octal`,
			},
		},

		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathVenafiFetchRead,
		},

		HelpSynopsis:    pathVenafiFetchHelpSyn,
		HelpDescription: pathVenafiFetchHelpDesc,
	}
}

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

func (b *backend) pathVenafiFetchRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (response *logical.Response, retErr error) {
	var serial, pemType, contentType string
	var certEntry *logical.StorageEntry
	var funcErr error
	var certificate []byte
	var revocationTime int64
	response = &logical.Response{
		Data: map[string]interface{}{},
	}

	switch {
	case req.Path == "crl" || req.Path == "crl/pem":
		serial = "crl"
		contentType = "application/pkix-crl"
		if req.Path == "crl/pem" {
			pemType = "X509 CRL"
		}
	case req.Path == "cert/crl":
		serial = "crl"
		pemType = "X509 CRL"
	default:
		serial = data.Get("serial").(string)
		pemType = "CERTIFICATE"
	}
	if len(serial) == 0 {
		response = logical.ErrorResponse("The serial number must be provided")
		goto reply
	}

	certEntry, funcErr = fetchCertBySerial(ctx, req, req.Path, serial)
	if funcErr != nil {
		switch funcErr.(type) {
		case errutil.UserError:
			response = logical.ErrorResponse(funcErr.Error())
			goto reply
		case errutil.InternalError:
			retErr = funcErr
			goto reply
		}
	}
	if certEntry == nil {
		response = nil
		goto reply
	}

	certificate = certEntry.Value

	if len(pemType) != 0 {
		block := pem.Block{
			Type:  pemType,
			Bytes: certEntry.Value,
		}
		certificate = []byte(strings.TrimSpace(string(pem.EncodeToMemory(&block))))
	}

	if funcErr != nil {
		switch funcErr.(type) {
		case errutil.UserError:
			response = logical.ErrorResponse(funcErr.Error())
			goto reply
		case errutil.InternalError:
			retErr = funcErr
			goto reply
		}
	}

reply:
	switch {
	case len(contentType) != 0:
		response = &logical.Response{
			Data: map[string]interface{}{
				logical.HTTPContentType: contentType,
				logical.HTTPRawBody:     certificate,
			}}
		if retErr != nil {
			if b.Logger().IsWarn() {
				b.Logger().Warn("Possible error, but cannot return in raw response. Note that an empty CA probably means none was configured, and an empty CRL is possibly correct", "error", retErr)
			}
		}
		retErr = nil
		if len(certificate) > 0 {
			response.Data[logical.HTTPStatusCode] = 200
		} else {
			response.Data[logical.HTTPStatusCode] = 204
		}
	case retErr != nil:
		response = nil
		return
	case response == nil:
		return
	case response.IsError():
		return response, nil
	default:
		response.Data["certificate"] = string(certificate)
		response.Data["revocation_time"] = revocationTime
	}

	return
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
