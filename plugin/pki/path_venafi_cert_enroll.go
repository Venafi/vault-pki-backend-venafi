package pki

import (
	"context"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"net"
	"regexp"
	"strings"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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
			"ip_sans": {
				Type:        framework.TypeCommaStringSlice,
				Description: "The requested IP SANs, if any, in a comma-delimited list",
			},
			"key_password": {
				Type:        framework.TypeString,
				Description: "Password for encrypting private key",
			},
			"custom_fields": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Use to specify custom fields in format 'key=value'. Use comma to separate multiple values: 'key1=value1,key2=value2'",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `The requested Time To Live for the certificate; sets the expiration date.
If not specified the role default is used. Cannot be larger than the role max TTL.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVenafiIssue,
				Summary:  "",
			},
		},

		HelpSynopsis:    pathVenafiCertEnrollHelp,
		HelpDescription: pathVenafiCertEnrollDesc,
	}
}

func pathVenafiCertSign(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: "sign/" + framework.GenericNameRegex("role"),
		Fields: map[string]*framework.FieldSchema{
			"csr": {
				Type:        framework.TypeString,
				Description: `PEM-format CSR to be signed.`,
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `The requested Time To Live for the certificate; sets the expiration date.
If not specified the role default is used. Cannot be larger than the role max TTL.`,
			},
			"role": {
				Type:        framework.TypeString,
				Description: `The desired role with configuration for this request`,
			},
			"custom_fields": {
				Type:        framework.TypeCommaStringSlice,
				Description: "Use to specify custom fields in format 'key=value'. Use comma to separate multiple values: 'key1=value1,key2=value2'",
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVenafiSign,
				Summary:  "",
			},
		},

		HelpSynopsis:    pathVenafiCertSignHelp,
		HelpDescription: pathVenafiCertSignDesc,
	}
}

func (b *backend) pathVenafiIssue(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

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

	return b.pathVenafiCertObtain(ctx, req, data, role, false)
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *backend) pathVenafiSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}

	return b.pathVenafiCertObtain(ctx, req, data, role, true)
}

func (b *backend) pathVenafiCertObtain(ctx context.Context, req *logical.Request, data *framework.FieldData, role *roleEntry, signCSR bool) (
	*logical.Response, error) {

	// When utilizing performance standbys in Vault Enterprise, this forces the call to be redirected to the primary since
	// a storage call is made after the API calls to issue the certificate.  This prevents the certificate from being
	// issued twice in this scenario.
	if !role.NoStore && b.System().ReplicationState().
		HasState(consts.ReplicationPerformanceStandby|consts.ReplicationPerformanceSecondary) {
		return nil, logical.ErrReadOnly
	}

	b.Logger().Debug("Getting the role\n")
	roleName := data.Get("role").(string)

	b.Logger().Debug("Creating Venafi client:")
	cl, timeout, err := b.ClientVenafi(ctx, req.Storage, data, req, roleName)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	var certReq *certificate.Request
	var reqData requestData

	if data == nil {
		return logical.ErrorResponse("data can't be nil"), nil
	}

	commonNameRaw, ok := data.GetOk("common_name")
	if ok {
		reqData.commonName = commonNameRaw.(string)
	}

	altNamesRaw, ok := data.GetOk("alt_names")
	if ok {
		reqData.altNames = altNamesRaw.([]string)
	}

	ipSANsRaw, ok := data.GetOk("ip_sans")
	if ok {
		reqData.ipSANs = ipSANsRaw.([]string)
	}

	keyPasswordRaw, ok := data.GetOk("key_password")
	if ok {
		reqData.keyPassword = keyPasswordRaw.(string)
	}

	csrStringRaw, ok := data.GetOk("csr")
	if ok {
		reqData.csrString = csrStringRaw.(string)
	}

	customFields, ok := data.GetOk("custom_fields")
	if ok {
		reqData.customFields = customFields.([]string)
	}

	if ttl, ok := data.GetOk("ttl"); ok {

		currentTTL := time.Duration(ttl.(int)) * time.Second
		//if specified role is greater than role's max ttl, then
		//role's max ttl will be used.
		if role.MaxTTL > 0 && currentTTL > role.MaxTTL {

			currentTTL = role.MaxTTL

		}

		reqData.ttl = currentTTL

	}

	certReq, err = formRequest(reqData, role, signCSR, b.Logger())
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	b.Logger().Debug("Making certificate request")
	err = cl.GenerateRequest(nil, certReq)
	if (err != nil) && (cl.GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		//catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(Token).*(not found)")

		//validate if the error is related to a expired access token, at this moment the only way can validate this is using the error message
		//and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED || regex.MatchString(msg) {
			cfg, err := b.getConfig(ctx, req, roleName, true)

			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}

			if cfg.Credentials.RefreshToken != "" {
				err = updateAccessToken(cfg, b, ctx, req, roleName)

				if err != nil {
					return logical.ErrorResponse(err.Error()), nil
				}

				//everything went fine so get the new client with the new refreshed access token
				cl, timeout, err = b.ClientVenafi(ctx, req.Storage, data, req, roleName)
				if err != nil {
					return logical.ErrorResponse(err.Error()), nil
				}

				b.Logger().Debug("Making certificate request again")

				err = cl.GenerateRequest(nil, certReq)
				if err != nil {
					return logical.ErrorResponse(err.Error()), nil
				}
			} else {
				return logical.ErrorResponse("Tried to get new access token, but refresh token is empty"), nil
			}
		} else {
			return logical.ErrorResponse(err.Error()), nil
		}
	}

	b.Logger().Debug("Running enroll request")

	requestID, err := cl.RequestCertificate(certReq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		Timeout:  timeout,
	}
	pcc, err := cl.RetrieveCertificate(pickupReq)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	pemBlock, _ := pem.Decode([]byte(pcc.Certificate))
	parsedCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	serialNumber, err := getHexFormatted(parsedCertificate.SerialNumber.Bytes(), ":")
	if err != nil {
		return nil, err
	}

	var entry *logical.StorageEntry
	chain := strings.Join(append([]string{pcc.Certificate}, pcc.Chain...), "\n")

	if !signCSR {
		err = pcc.AddPrivateKey(certReq.PrivateKey, []byte(data.Get("key_password").(string)))
		if err != nil {
			return nil, err
		}
	}

	if role.StorePrivateKey && !signCSR {
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
	if err != nil {
		return nil, err
	}

	//if no_store is not specified
	if !role.NoStore {
		if role.StoreBy == storeByCNString {
			//Writing certificate to the storage with CN
			b.Logger().Debug("Writing certificate to the certs/" + reqData.commonName)
			entry.Key = "certs/" + reqData.commonName

			if err := req.Storage.Put(ctx, entry); err != nil {
				b.Logger().Error("Error putting entry to storage: " + err.Error())
				return nil, err
			}
		} else {
			//Writing certificate to the storage with Serial Number
			b.Logger().Debug("Putting certificate to the certs: " + normalizeSerial(serialNumber))
			entry.Key = "certs/" + normalizeSerial(serialNumber)

			if err := req.Storage.Put(ctx, entry); err != nil {
				b.Logger().Error("Error putting entry to storage: " + err.Error())
				return nil, err
			}
		}

	}

	var respData map[string]interface{}
	if !signCSR {
		respData = map[string]interface{}{
			"common_name":       reqData.commonName,
			"serial_number":     serialNumber,
			"certificate_chain": chain,
			"certificate":       pcc.Certificate,
			"private_key":       pcc.PrivateKey,
		}
	} else {
		respData = map[string]interface{}{
			"common_name":       reqData.commonName,
			"serial_number":     serialNumber,
			"certificate_chain": chain,
			"certificate":       pcc.Certificate,
		}
	}

	var logResp *logical.Response
	switch {
	case !role.GenerateLease:
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
		TTL := time.Until(parsedCertificate.NotAfter)
		b.Logger().Debug("Setting up secret lease duration to: " + TTL.String())
		logResp.Secret.TTL = TTL
	}

	if !signCSR {
		logResp.AddWarning("Read access to this endpoint should be controlled via ACLs as it will return the connection private key as it is.")
	}
	return logResp, nil
}

type requestData struct {
	commonName   string
	altNames     []string
	ipSANs       []string
	keyPassword  string
	csrString    string
	customFields []string
	ttl          time.Duration
}

func formRequest(reqData requestData, role *roleEntry, signCSR bool, logger hclog.Logger) (certReq *certificate.Request, err error) {
	if !signCSR {
		if len(reqData.commonName) == 0 && len(reqData.altNames) == 0 {
			return certReq, fmt.Errorf("no domains specified on certificate")
		}
		if len(reqData.commonName) == 0 && len(reqData.altNames) > 0 {
			reqData.commonName = reqData.altNames[0]
		}
		if !sliceContains(reqData.altNames, reqData.commonName) {
			logger.Debug(fmt.Sprintf("Adding CN %s to SAN %s because it wasn't included.", reqData.commonName, reqData.altNames))
			reqData.altNames = append(reqData.altNames, reqData.commonName)
		}
		certReq = &certificate.Request{
			Subject: pkix.Name{
				CommonName: reqData.commonName,
			},
			CsrOrigin:   certificate.LocalGeneratedCSR,
			KeyPassword: reqData.keyPassword,
		}
		ipSet := make(map[string]struct{})
		nameSet := make(map[string]struct{})
		for _, v := range reqData.altNames {
			if strings.Contains(v, "@") {
				certReq.EmailAddresses = append(certReq.EmailAddresses, v)
			} else if net.ParseIP(v) != nil {
				ipSet[v] = struct{}{}
				nameSet[v] = struct{}{}
			} else {
				nameSet[v] = struct{}{}
			}
		}
		for _, v := range reqData.ipSANs {
			if net.ParseIP(v) != nil {
				ipSet[v] = struct{}{}
			}
		}
		for ip := range ipSet {
			certReq.IPAddresses = append(certReq.IPAddresses, net.ParseIP(ip))
		}
		for k := range nameSet {
			certReq.DNSNames = append(certReq.DNSNames, k)
		}

	} else {
		logger.Debug("Signing user provided CSR")

		if reqData.csrString == "" {
			return certReq, fmt.Errorf("\"csr\" is empty")
		}
		pemBytes := []byte(reqData.csrString)
		pemBlock, _ := pem.Decode(pemBytes)
		if pemBlock == nil {
			return certReq, fmt.Errorf("csr contains no data")
		}
		csr, err := x509.ParseCertificateRequest(pemBlock.Bytes)
		if err != nil {
			return certReq, fmt.Errorf("can't parse provided CSR %v", err)
		}
		reqData.commonName = csr.Subject.CommonName
		certReq = &certificate.Request{
			CsrOrigin: certificate.UserProvidedCSR,
		}
		err = certReq.SetCSR(pemBytes)
		if err != nil {
			return certReq, err
		}
	}

	if !signCSR {
		if role.KeyType == "rsa" {
			certReq.KeyLength = role.KeyBits
		} else if role.KeyType == "ec" {
			certReq.KeyType = certificate.KeyTypeECDSA
			switch {
			case role.KeyCurve == "P256":
				certReq.KeyCurve = certificate.EllipticCurveP256
			case role.KeyCurve == "P384":
				certReq.KeyCurve = certificate.EllipticCurveP384
			case role.KeyCurve == "P521":
				certReq.KeyCurve = certificate.EllipticCurveP521
			default:
				return certReq, fmt.Errorf("can't use key curve %s", role.KeyCurve)
			}

		} else {
			return certReq, fmt.Errorf("can't determine key algorithm for %s", role.KeyType)
		}
	}

	if role.ChainOption == "first" {
		certReq.ChainOption = certificate.ChainOptionRootFirst
	} else if role.ChainOption == "last" {
		certReq.ChainOption = certificate.ChainOptionRootLast
	} else {
		return certReq, fmt.Errorf("invalid chain option %s", role.ChainOption)
	}

	if reqData.ttl > 0 {

		certReq.IssuerHint = getIssuerHint(role.IssuerHint)

		ttl := int(reqData.ttl.Hours())
		certReq.ValidityHours = ttl

	} else if role.TTL > 0 {

		certReq.IssuerHint = getIssuerHint(role.IssuerHint)

		ttl := int(role.TTL.Hours())
		certReq.ValidityHours = ttl
	}

	//Adding origin custom field with utility name to certificate metadata
	certReq.CustomFields = []certificate.CustomField{{Type: certificate.CustomFieldOrigin, Value: utilityName}}

	//Adding custom fields to certificate
	if !isValidCustomFields(reqData.customFields) {
		return certReq, fmt.Errorf("invalid custom fields; must be 'key=value' using commas to separate multiple key-value pairs")
	}
	for _, f := range reqData.customFields {
		tuple := strings.Split(f, "=")
		if len(tuple) == 2 {
			name := strings.TrimSpace(tuple[0])
			value := strings.TrimSpace(tuple[1])
			certReq.CustomFields = append(certReq.CustomFields, certificate.CustomField{Name: name, Value: value})
		}
	}

	return certReq, nil
}

func getIssuerHint(is string) string {

	issuerHint := ""

	if is != "" {

		issuerOpt := string(is[0])
		issuerOpt = strings.ToLower(issuerOpt)

		switch issuerOpt {

		case "m":
			issuerHint = util.IssuerHintMicrosoft
		case "d":
			issuerHint = util.IssuerHintDigicert
		case "e":
			issuerHint = util.IssuerHintEntrust
		}

	}

	return issuerHint

}

func isValidCustomFields(customFields []string) bool {
	//Any character is accepted as key, any character is accepted as value
	regex, err := regexp.Compile("^([^=]+=[^=]+)$")
	if err != nil {
		return false
	}
	if len(customFields) > 0 {
		for _, data := range customFields {
			if !regex.MatchString(data) {
				return false
			}
		}
	}

	return true
}

type VenafiCert struct {
	Certificate      string `json:"certificate"`
	CertificateChain string `json:"certificate_chain"`
	PrivateKey       string `json:"private_key"`
	SerialNumber     string `json:"serial_number"`
}

const (
	pathConfigRootHelpSyn = `
Configure the Venafi TPP credentials that are used to manage certificates,
`
	pathConfigRootHelpDesc = `
Configure TPP first
`
	pathVenafiCertEnrollHelp = `
Enroll Venafi certificate
`
	pathVenafiCertEnrollDesc = `
Enroll Venafi certificate
`
	pathVenafiCertSignHelp = `
Sign Venafi certificate
`
	pathVenafiCertSignDesc = `
Sign Venafi certificate
`
)
