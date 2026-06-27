package pki

import (
	"context"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathVenafiCertRead(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: `cert/(?P<certificate_uid>[^/]+)`,
		Fields: map[string]*framework.FieldSchema{
			"certificate_uid": {
				Type:        framework.TypeString,
				Description: "Common name or serial number of desired certificate",
			},
			"key_password": {
				Type:        framework.TypeString,
				Description: "Password for encrypting private key",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation:   b.pathVenafiCertRead,
			logical.DeleteOperation: b.pathVenafiCertDelete,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) pathVenafiCertRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	b.Logger().Debug("Trying to read certificate")
	certUID := data.Get("certificate_uid").(string)
	if len(certUID) == 0 {
		return logical.ErrorResponse("no common name specified on certificate"), nil
	}

	keyPassword := data.Get("key_password").(string)

	cert, err := loadCertificateFromStorage(b, ctx, req, certUID, keyPassword)
	if err != nil {
		return nil, err
	}

	respData := map[string]interface{}{
		"certificate_uid":   certUID,
		"serial_number":     cert.SerialNumber,
		"certificate_chain": cert.CertificateChain,
		"certificate":       cert.Certificate,
	}

	return &logical.Response{
		//Data: structs.New(cert).Map(),
		Data: respData,
	}, nil
}

func (b *backend) pathVenafiCertDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	certUID := data.Get("certificate_uid").(string)
	if len(certUID) == 0 {
		return logical.ErrorResponse("no common name specified on certificate"), nil
	}

	if err := req.Storage.Delete(ctx, "certs/"+certUID); err != nil {
		return nil, err
	}

	return nil, nil
}
