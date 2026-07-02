package pki

import (
	"context"
	"crypto/sha1" // #nosec G505
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
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
			"serial_number": {
				Type:        framework.TypeString,
				Description: "Serial number of the certificate to revoke",
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

	id := getRevokeCertificateID(d, role)
	if id == "" {
		return logical.ErrorResponse("missing certificate_uid or serial_number"), nil
	}

	if exists, err := isCertificateStored(ctx, req, id, role); !exists {
		if err != nil {
			return logical.ErrorResponse(err.Error()), nil
		}
		return logical.ErrorResponse("the certificate is not stored"), nil
	}

	// Load the stored certificate to verify ownership
	storedCert, err := loadCertificateFromStorage(b, ctx, req, id, "")
	if err != nil {
		return logical.ErrorResponse("failed to load certificate: %s", err), err
	}

	// Verify that the certificate belongs to the requested role
	if storedCert.Role != "" && storedCert.Role != roleName {
		return logical.ErrorResponse("certificate does not belong to role %s", roleName), errors.New("unauthorized revocation attempt")
	}

	b.Logger().Debug("Creating Venafi client:")

	cl, cfg, err := b.ClientVenafi(ctx, req, role)

	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	revReq, err := getRevocationRequest(b, &cl, ctx, req, cfg.Zone, id, role)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	_, err = cl.RevokeCertificate(revReq)

	if err != nil {
		return logical.ErrorResponse("Failed to revoke certificate: %s", err), nil
	}

	err = deleteCertificateEntry(ctx, req, id, role)
	if err != nil {
		return logical.ErrorResponse("Certificate was revoked, but failed to remove it from vault: %s", err), nil

	}

	return nil, nil
}

func getRevokeCertificateID(d *framework.FieldData, role *roleEntry) string {
	id := d.Get("certificate_uid").(string)
	if id == "" {
		id = d.Get("serial_number").(string)
	}
	return normalizeRevokeCertificateID(id, role)
}

func normalizeRevokeCertificateID(id string, role *roleEntry) string {
	if id == "" {
		return id
	}
	if role.StoreBy == util.StoreByCNString || role.StoreByCN {
		return id
	}
	return util.NormalizeSerial(id)
}

func deleteCertificateEntry(ctx context.Context, req *logical.Request, id string, role *roleEntry) error {

	id = normalizeRevokeCertificateID(id, role)

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
		return false, errors.New("certificate is not stored")
	}

	id = normalizeRevokeCertificateID(id, role)

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

func getRevocationRequest(b *backend, c *endpoint.Connector, ctx context.Context, req *logical.Request, zone string, certID string, role *roleEntry) (*certificate.RevocationRequest, error) {
	revReq := certificate.RevocationRequest{}

	// Cloud/VaaS and NGTS (Strata Cloud Manager) revoke by certificate thumbprint
	// (they ignore CertificateDN, and NGTS's SearchCertificates panics). The
	// thumbprint is computed locally from the stored certificate, so no server
	// search is needed for either backend.
	connectorType := (*c).GetType()
	if connectorType == endpoint.ConnectorTypeCloud || connectorType == endpoint.ConnectorTypeNGTS {
		thumbprint, err := getThumbprintFromStorage(b, ctx, req, certID)
		if err != nil {
			return nil, err
		}
		revReq.Thumbprint = thumbprint
		return &revReq, nil
	}

	dn, err := getDn(b, c, ctx, req, zone, certID, role.StoreBy)
	if err != nil {
		return nil, err
	}
	revReq.CertificateDN = dn

	return &revReq, nil
}

func getThumbprintFromStorage(b *backend, ctx context.Context, req *logical.Request, certID string) (string, error) {
	cert, err := loadCertificateFromStorage(b, ctx, req, certID, "")
	if err != nil {
		return "", err
	}

	block, _ := pem.Decode([]byte(cert.Certificate))
	if block == nil {
		return "", errors.New("failed to parse stored certificate PEM")
	}

	parsedCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return "", err
	}

	thumbprint := sha1.Sum(parsedCert.Raw)
	return strings.ToUpper(hex.EncodeToString(thumbprint[:])), nil
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
		return "", errors.New("unknown role type of uid for storage")
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
	if len(data.Certificates) == 0 {
		return "", errors.New("no certificates found for the given serial")
	}
	dn := data.Certificates[0].CertificateRequestId

	return dn, nil

}
