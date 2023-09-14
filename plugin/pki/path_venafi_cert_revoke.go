package pki

import (
	"context"
	"fmt"
	"strings"

	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/Venafi/vcert/v5/pkg/policy"
	vcertutil "github.com/Venafi/vcert/v5/pkg/util"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

func pathVenafiCertRevoke(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "revoke/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `The desired role with configuration for this request`,
			},
			"certificate_uid": {
				Type:        framework.TypeString,
				Description: "Common name for created certificate",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.venafiCertRevoke,
			},
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) venafiCertRevoke(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {

	op := req.Operation
	if op == logical.RevokeOperation {
		return nil, nil
	}

	b.Logger().Debug("Getting the role\n")
	roleName := d.Get("role").(string)

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	if role.KeyType == "any" {
		return logical.ErrorResponse("role key type \"any\" not allowed for issuing certificates, only signing"), nil
	}

	id := d.Get("certificate_uid").(string)

	if exists, err := isCertificateStored(ctx, req, id, role); !exists {
		if err != nil {
			return logical.ErrorResponse(err.Error()), err
		}
		return logical.ErrorResponse("the certificate is not stored"), fmt.Errorf("the certificate is not stored")
	}

	b.Logger().Debug("Creating Venafi client:")

	cl, cfg, err := b.ClientVenafi(ctx, req, role)

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	dn, err := getDn(b, &cl, ctx, req, cfg.Zone, id, role.StoreBy)

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	revReq := certificate.RevocationRequest{}

	revReq.CertificateDN = dn

	err = cl.RevokeCertificate(&revReq)

	if err != nil {
		return logical.ErrorResponse("Failed to revoke certificate: %s", err), nil
	}

	err = deleteCertificateEntry(ctx, req, id, role)
	if err != nil {
		return logical.ErrorResponse("Certificate was revoked, but failed to remove it from vault: %s", err), nil

	}

	return nil, nil
}

func deleteCertificateEntry(ctx context.Context, req *logical.Request, id string, role *roleEntry) error {

	if !role.StoreByCN {
		id = strings.ReplaceAll(id, ":", "-")
	}

	path := "certs/" + id

	//remove the certificate from vault.
	err := req.Storage.Delete(ctx, path)

	if err != nil {
		return err
	}

	return nil

}

func isCertificateStored(ctx context.Context, req *logical.Request, id string, role *roleEntry) (bool, error) {

	//there is nothing to remove.
	if role.NoStore {
		return false, fmt.Errorf("certificate is not stored")
	}

	if !role.StoreByCN {
		if strings.Contains(id, ":") {
			id = strings.ReplaceAll(id, ":", "-")
		}
		if strings.Contains(id, "-") {
			id = strings.ReplaceAll(id, "-", "-")
		}
	}

	path := "certs/" + id
	entry, err := req.Storage.Get(ctx, path)

	if err != nil {
		return false, err
	}

	if entry == nil {
		return false, nil
	}

	return true, nil
}

func getDn(b *backend, c *endpoint.Connector, ctx context.Context, req *logical.Request, zone string, CertId string, storeByType string) (string, error) {

	dn := CertId
	switch storeByType {
	case util.StoreBySerialString:
		return getDnFromSerial(c, CertId)
	case util.StoreByCNString:
		if (*c).GetType() == endpoint.ConnectorTypeTPP {

			if !strings.HasPrefix(zone, vcertutil.PathSeparator) {
				zone = vcertutil.PathSeparator + zone
			}

			if !strings.HasPrefix(zone, policy.RootPath) {
				zone = policy.RootPath + zone

			}

			if !strings.HasPrefix(dn, zone) {
				dn = fmt.Sprintf("%s\\%s", zone, CertId)
			}

		}
	case util.StoreByHASHstring:
		cert, err := loadCertificateFromStorage(b, ctx, req, CertId, "")
		if err != nil {
			return "", err
		}
		serialNumber := strings.ReplaceAll(cert.SerialNumber, ":", "")
		return getDnFromSerial(c, serialNumber)
	default:
		return "", fmt.Errorf("unknown role type of uid for storage")
	}

	return dn, nil

}

func getDnFromSerial(c *endpoint.Connector, serial string) (string, error) {
	var reqS certificate.SearchRequest
	//removing dash from serial since TPP does not contain them
	tppSerial := strings.ReplaceAll(serial, "-", "")
	reqS = append(reqS, fmt.Sprintf("serial=%s", tppSerial))
	data, err := (*c).SearchCertificates(&reqS)
	if err != nil {
		return "", err
	}
	dn := data.Certificates[0].CertificateRequestId

	return dn, nil

}
