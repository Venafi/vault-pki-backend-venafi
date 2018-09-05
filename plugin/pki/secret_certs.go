package pki

import (
	"github.com/hashicorp/vault/logical/framework"
)

// SecretCertsType is the name used to identify this type
const SecretCertsType = "pki"

func secretCerts(b *backend) *framework.Secret {
	return &framework.Secret{
		Type: SecretCertsType,
		Fields: map[string]*framework.FieldSchema{
			"certificate": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The PEM-encoded concatenated certificate and
issuing certificate authority`,
			},
			"private_key": &framework.FieldSchema{
				Type:        framework.TypeString,
				Description: "The PEM-encoded private key for the certificate",
			},
			"serial": &framework.FieldSchema{
				Type: framework.TypeString,
				Description: `The serial number of the certificate, for handy
reference`,
			},
		},

		Revoke: b.venafiCertRevoke,
	}
}
