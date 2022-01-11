package pki

import (
	"context"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/policy"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
	"strings"
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
			return logical.ErrorResponse(err.Error()), nil
		}
		return logical.ErrorResponse("the certificate is not stored"), nil
	}

	b.Logger().Debug("Creating Venafi client:")
	cl, _, err := b.ClientVenafi(ctx, req.Storage, d, req, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	dn, err := getDn(b, &cl, ctx, req, roleName, id, role.StoreByCN)

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
		if strings.Contains(id, ":"){
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

func getDn(b *backend, c *endpoint.Connector, ctx context.Context, req *logical.Request, rn, id string, storeByCN bool) (string, error) {

	if !storeByCN {
		return getDnFromSerial(c, id)
	}

	dn := id
	if (*c).GetType() == endpoint.ConnectorTypeTPP {
		cfg, err := b.getConfig(ctx, req, rn, false)
		if err != nil {
			return "", err
		}

		zone := cfg.Zone

		if !strings.HasPrefix(zone, util.PathSeparator) {
			zone = util.PathSeparator + zone
		}

		if !strings.HasPrefix(zone, policy.RootPath) {
			zone = policy.RootPath + zone

		}

		if !strings.HasPrefix(dn, zone) {
			dn = fmt.Sprintf("%s\\%s", zone, id)
		}

	}

	return dn, nil

}

func getDnFromSerial(c *endpoint.Connector, id string) (string, error){
	/*var reqS certificate.SearchRequest
	reqS = append(reqS, fmt.Sprintf("serial=%s", id))
	data, err := c.SearchCertificates(&reqS)
	if err != nil{
	return "", error
	}
	 dn := data.Certificates[0].CertificateRequestId

	return dn, nil
	*/


	return "", nil
}