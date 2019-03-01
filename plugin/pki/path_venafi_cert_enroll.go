package pki

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/pkg/certificate"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
	"log"
	"net"
	"strings"
	"time"
)

func pathVenafiCertEnroll(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "issue/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"role": {
				Type:        framework.TypeString,
				Description: `The desired role with configuration for this request`,
			},
			"common_name": {
				Type:        framework.TypeString,
				Description: "Common name for created certificate",
			},
			"alt_names": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Alternative names for created certificate. Email and IP addresses can be specified too",
			},
		},
		Callbacks: map[logical.Operation]framework.OperationFunc{
			logical.UpdateOperation: b.pathVenafiCertObtain,
		},

		HelpSynopsis:    pathConfigRootHelpSyn,
		HelpDescription: pathConfigRootHelpDesc,
	}
}

func (b *backend) pathVenafiCertObtain(ctx context.Context, req *logical.Request, data *framework.FieldData) (
	*logical.Response, error) {

	log.Printf("Getting the role\n")
	roleName := data.Get("role").(string)

	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("Unknown role +%v", role)
	}

	commonName := data.Get("common_name").(string)
	altNames := data.Get("alt_names").([]string)
	if len(commonName) == 0 && len(altNames) == 0 {
		return logical.ErrorResponse("no domains specified on certificate"), nil
	}
	if len(commonName) == 0 && len(altNames) > 0 {
		commonName = altNames[0]
	}

	log.Println("Running venafi client:")
	cl, err := b.ClientVenafi(ctx, req.Storage, data, req, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if len(commonName) == 0 && len(altNames) == 0 {
		return logical.ErrorResponse("no domains specified on certificate"), nil
	}
	if len(commonName) == 0 && len(altNames) > 0 {
		commonName = altNames[0]
	}
	if !sliceContains(altNames, commonName) {
		log.Printf("Adding CN %s to SAN because it wasn't included.", commonName)
		altNames = append(altNames, commonName)
	}
	certReq := &certificate.Request{
		Subject: pkix.Name{
			CommonName: commonName,
		},
		CsrOrigin: certificate.LocalGeneratedCSR,
		//TODO: add key password support
	}

	for _,v := range altNames {
		if strings.Contains(v, "@") {
			certReq.EmailAddresses = append(certReq.DNSNames, v)
		} else if net.ParseIP(v) != nil {
			certReq.IPAddresses = append([]net.IP{}, net.ParseIP(v))
		}
	}

	if role.KeyType == "rsa" {
		certReq.KeyLength = role.KeyBits
	} else if role.KeyType == "ec" {
		certReq.KeyType = certificate.KeyTypeECDSA
		switch {
		case role.KeyCurve == "P224":
			certReq.KeyCurve = certificate.EllipticCurveP224
		case role.KeyCurve == "P256":
			certReq.KeyCurve = certificate.EllipticCurveP256
		case role.KeyCurve == "P384":
			certReq.KeyCurve = certificate.EllipticCurveP384
		case role.KeyCurve == "P521":
			certReq.KeyCurve = certificate.EllipticCurveP521
		default:
			return logical.ErrorResponse(fmt.Sprintf("can't use key curve %s", role.KeyCurve)), nil
		}

	} else {
		return logical.ErrorResponse(fmt.Sprintf("can't determine key algorithm for %s", role.KeyType)), nil
	}


	if role.ChainOption == "first" {
		certReq.ChainOption = certificate.ChainOptionRootFirst
	} else if role.ChainOption == "last" {
		certReq.ChainOption = certificate.ChainOptionRootLast
	} else {
		return logical.ErrorResponse(fmt.Sprintf("Invalid chain option %s", role.ChainOption)), nil
	}

	log.Println("Making certificate request")
	err = cl.GenerateRequest(nil, certReq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	log.Printf("Running enroll request")

	requestID, err := cl.RequestCertificate(certReq, "")
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		//TODO: make timeout configurable
		Timeout:  180 * time.Second,
	}
	pcc, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	pemBlock, _ := pem.Decode([]byte(pcc.Certificate))
	parsedCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	serialNumber := getHexFormatted(parsedCertificate.SerialNumber.Bytes(), ":")


	var entry *logical.StorageEntry
	chain := strings.Join(append([]string{pcc.Certificate}, pcc.Chain...), "\n")
	pcc.AddPrivateKey(certReq.PrivateKey, []byte(""))
	if role.StorePrivateKey {
		entry, err = logical.StorageEntryJSON("", VenafiCert{
			Certificate:      pcc.Certificate,
			CertificateChain: chain,
			PrivateKey:       pcc.PrivateKey,
			SerialNumber:     serialNumber,
		})
	} else {
		entry, err = logical.StorageEntryJSON("", VenafiCert{
			Certificate:      pcc.Certificate,
			CertificateChain: chain,
			SerialNumber:     serialNumber,
		})
	}

	if role.StoreByCN {

		//Writing certificate to the storage with CN
		log.Println("Putting certificate to the certs/" + commonName)
		entry.Key = "certs/" + commonName

		if err := req.Storage.Put(ctx, entry); err != nil {
			log.Println("Error putting entry to storage")
			return nil, err
		}
	}

	if role.StoreBySerial {

		//Writing certificate to the storage with Serial Number
		log.Println("Putting certificate to the certs/", normalizeSerial(serialNumber))
		entry.Key = "certs/" + normalizeSerial(serialNumber)

		if err := req.Storage.Put(ctx, entry); err != nil {
			log.Println("Error putting entry to storage")
			return nil, err
		}
	}

	respData := map[string]interface{}{
		"common_name":       commonName,
		"serial_number":     serialNumber,
		"certificate_chain": chain,
		"certificate":       pcc.Certificate,
		"private_key":       pcc.PrivateKey,
	}

	var logResp *logical.Response
	switch {
	case role.GenerateLease == false:
		// If lease generation is disabled do not populate `Secret` field in
		// the response
		logResp = &logical.Response{
			Data: respData,
		}
	default:
		logResp = b.Secret(SecretCertsType).Response(
			respData,
			map[string]interface{}{
				"serial_number": serialNumber,
			})
		TTL := parsedCertificate.NotAfter.Sub(time.Now())
		log.Println("Seting up secret lease duration to: ", TTL)
		logResp.Secret.TTL = TTL
	}

	logResp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the connection private key as it is.")
	return logResp, nil
}


type VenafiCert struct {
	Certificate      string `json:"certificate"`
	CertificateChain string `json:"certificate_chain"`
	PrivateKey       string `json:"private_key"`
	SerialNumber     string `json:"serial_number"`
}

const pathConfigRootHelpSyn = `
Configure the Venafi TPP credentials that are used to manage certificates,
`

const pathConfigRootHelpDesc = `
Configure TPP first
`
