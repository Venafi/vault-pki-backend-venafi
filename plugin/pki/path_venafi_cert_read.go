package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
)

func pathVenafiCertRead(b *backend) *framework.Path {
	return &framework.Path{
		//Pattern: "certs/(?P<certificate_uid>[0-9a-z-.]+)",
		Pattern: "cert/" + framework.GenericNameRegex("certificate_uid"),
		Fields: map[string]*framework.FieldSchema{
			"certificate_uid": {
				Type:        framework.TypeString,
				Description: "Common name or serial number of desired certificate",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.ReadOperation: b.pathVenafiCertRead,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) pathVenafiCertRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	log.Printf("Trying to read certificate")
	certUID := data.Get("certificate_uid").(string)
	if len(certUID) == 0 {
		return logical.ErrorResponse("no common name specified on certificate"), nil
	}

	entry, err := req.Storage.Get(ctx, "certs/"+certUID)
	if err != nil {
		return nil, fmt.Errorf("failed to read Venafi certificate")
	}
	var cert VenafiCert
	log.Println("Getting venafi certificate")
	log.Println("certificate:", cert.Certificate)
	e := entry.DecodeJSON(&cert)
	log.Println("e:", e)
	if err := entry.DecodeJSON(&cert); err != nil {
		log.Printf("error reading venafi configuration: %s", err)
		return nil, err
	}
	log.Println("chain is:", cert.Certificate)

	respData := map[string]interface{}{
		"certificate_uid":   certUID,
		"serial_number":     cert.SerialNumber,
		"certificate_chain": cert.CertificateChain,
		"certificate":       cert.Certificate,
		"private_key":       cert.PrivateKey,
	}

	return &logical.Response{
		//Data: structs.New(cert).Map(),
		Data: respData,
	}, nil
}
