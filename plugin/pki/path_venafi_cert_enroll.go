package pki

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Venafi/vcert/v5"
	"github.com/Venafi/vcert/v5/pkg/certificate"
	"github.com/Venafi/vcert/v5/pkg/endpoint"
	vcertutil "github.com/Venafi/vcert/v5/pkg/util"
	"github.com/Venafi/vcert/v5/pkg/verror"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki/vpkierror"
	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

type SyncedResponse struct {
	logResponse *logical.Response
	condition   *sync.Cond
	error       error
}

var cache = map[string]*SyncedResponse{}

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
			"private_key_format": {
				Type:        framework.TypeString,
				Description: "For specifiying the private key format ",
			},
			"custom_fields": {
				Type:        framework.TypeString,
				Description: "Use to specify custom fields in format 'key=value'. Use comma to separate multiple values: 'key1=value1,key2=value2'",
			},
			"ttl": {
				Type: framework.TypeDurationSecond,
				Description: `The requested Time To Live for the certificate; sets the expiration date.
If not specified the role default is used. Cannot be larger than the role max TTL.`,
			},
			"retry": {
				Type:        framework.TypeBool,
				Description: "Used to specify to retry (once) issuance of certificate if any error occurred",
			},
			"min_cert_time_left": {
				Type:        framework.TypeDurationSecond,
				Description: `When set, is used to determinate if certificate issuance is needed comparing certificate validity against desired remaining validity`,
				Default:     time.Duration(30*24) * time.Hour,
			},
			"ignore_local_storage": {
				Type:        framework.TypeBool,
				Description: `When true, bypasses prevent re-issue logic to issue new certificate'`,
				Default:     false,
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
				Type:        framework.TypeString,
				Description: "Use to specify custom fields in format 'key=value'. Use comma to separate multiple values: 'key1=value1,key2=value2'",
			},
			"retry": {
				Type:        framework.TypeBool,
				Description: "Used to specify to retry (once) issuance of certificate if any error occurred",
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
	b.Logger().Debug(fmt.Sprintf("Using role: %s", roleName))
	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	role.Name = roleName
	if err != nil {
		return nil, err
	}
	if role == nil {
		return nil, fmt.Errorf("unknown role: %s", roleName)
	}

	if role.KeyType == "any" {
		return nil, fmt.Errorf(`role key type "any" not allowed for issuing certificates, only signing`)
	}

	logicResp, err := b.pathVenafiCertObtain(ctx, req, data, role, false)
	if err != nil {
		return nil, err
	}
	return logicResp, nil
}

// pathSign issues a certificate from a submitted CSR, subject to role
// restrictions
func (b *backend) pathVenafiSign(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	roleName := data.Get("role").(string)

	// Get the role
	role, err := b.getRole(ctx, req.Storage, roleName)
	role.Name = roleName

	if err != nil {
		return nil, err
	}
	if role == nil {
		return logical.ErrorResponse(fmt.Sprintf("unknown role: %s", roleName)), nil
	}
	logicResp, err := b.pathVenafiCertObtain(ctx, req, data, role, true)
	if err != nil {
		return nil, err
	}

	return logicResp, nil
}

func (b *backend) pathVenafiCertObtain(ctx context.Context, logicalRequest *logical.Request, data *framework.FieldData, role *roleEntry, signCSR bool) (
	*logical.Response, error) {

	var logResp *logical.Response

	b.Logger().Info("Creating Venafi client:")

	// here we already filter proper "Zone" to later use with cfg.Zone
	connector, cfg, err := b.ClientVenafi(ctx, logicalRequest, role)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("error creating Venafi connector: %s", err.Error()))
		return nil, err
	}

	if connector.GetType() == endpoint.ConnectorTypeTPP {
		var secretEntry *venafiSecretEntry
		secretEntry, err = b.getVenafiSecret(ctx, logicalRequest.Storage, role.VenafiSecret)
		if err != nil {
			return nil, err
		}
		if secretEntry.RefreshToken != "" && secretEntry.RefreshToken2 != "" {
			connector, err = validateAccessToken(b, ctx, connector, cfg, logicalRequest, role)
			if err != nil {
				b.Logger().Error(fmt.Sprintf("error validating access token: %s", err.Error()))
				return nil, err
			}
		}
	}

	reqData, err := populateReqData(data, role)
	if err != nil {
		b.Logger().Error("error populating data to request: %s", err.Error())
		return nil, err
	}

	var certId string
	// we currently ignore workflow for signingCSR because we are not supporting "hash" mode for it. That applies to every
	// "hash" related workflow.
	// we don't validate ignoring the local storage because we are making the "hash" mode independent of the prevent-reissue feature
	if !role.NoStore && role.StoreBy == util.StoreByHASHstring && !signCSR {
		certId = getCertIdHash(*reqData, cfg.Zone, b.Logger())
	}

	// Checking if we need to ignore local storage
	var ignoreLocalStorage bool // default is false

	// If the ignoreLocalStorage flag has been declared during issue path level, it takes priority over the ignoreLocalStorage
	// flag in the Venafi Role
	ignoreLocalRaw, ok := data.GetOk("ignore_local_storage")
	if ok {
		ignoreLocalStorage = ignoreLocalRaw.(bool)
	} else {
		ignoreLocalStorage = role.IgnoreLocalStorage
	}

	if !ignoreLocalStorage && role.StorePrivateKey && role.StoreBy == util.StoreBySerialString && !signCSR {
		// if we don't receive a logic response, whenever is an error or the actual certificate found in storage
		// means we need to issue a new one
		logicalResp := preventReissue(b, ctx, logicalRequest, reqData, &connector, role, cfg.Zone, data)
		if logicalResp != nil {
			return logicalResp, nil
		}
	} else if !ignoreLocalStorage && role.StorePrivateKey && role.StoreBy == util.StoreByHASHstring && !signCSR {
		b.Logger().Info(fmt.Sprintf("Calling prevent local for hash %v", certId))
		logicalResp := preventReissueLocal(b, ctx, logicalRequest, reqData, role, certId, data)
		if logicalResp != nil {
			return logicalResp, nil
		}
	}

	// When utilizing performance standbys in Vault Enterprise, this forces the call to be redirected to the primary since
	// a storage call is made after the API calls to issue the certificate.  This prevents the certificate from being
	// issued twice in this scenario.
	if !role.NoStore && b.System().ReplicationState().
		HasState(consts.ReplicationPerformanceStandby|consts.ReplicationPerformanceSecondary) {
		return nil, logical.ErrReadOnly
	}

	// if user is using store by hash
	var cert *SyncedResponse
	if !signCSR && role.StoreBy == util.StoreByHASHstring {
		found := false
		b.Logger().Info("locking process to update cache")
		b.mux.Lock()
		cert, found = cache[certId]
		if found {
			b.Logger().Info(fmt.Sprintf("Request is waiting on previous request on certificate to be issued for hash %v", certId))
			cert.condition.Wait()
			b.mux.Unlock()
			b.Logger().Info(fmt.Sprintf("Returning the certificate for hash %v retrieved from previous request.", certId))
			if cert.error != nil {
				b.Logger().Error("waiting state error: %s", cert.error.Error())
				return nil, cert.error
			}
			return cert.logResponse, nil
		}
		newCond := sync.NewCond(&b.mux)
		cert = &SyncedResponse{
			logResponse: nil,
			condition:   newCond,
			error:       nil,
		}
		cache[certId] = cert
		b.mux.Unlock()
	}

	var certReq *certificate.Request
	certReq, err = formRequest(*reqData, role, &connector, signCSR, b.Logger())
	if err != nil {
		if !signCSR && role.StoreBy == util.StoreByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error forming request: %s", err.Error())
		return logical.ErrorResponse(err.Error()), nil
	}

	err = createCertificateRequest(b, &connector, ctx, logicalRequest, role, certReq)
	if err != nil {
		if !signCSR && role.StoreBy == util.StoreByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error creating certificate request: %s", err.Error())
		return nil, err
	}
	var pcc *certificate.PEMCollection
	pcc, err = runningEnrollRequest(b, data, certReq, connector, role, signCSR)
	if err != nil {
		if !signCSR && role.StoreBy == util.StoreByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error running enroll request: %s", err.Error())
		return nil, err
	}

	parsedCertificate, err := b.parseCertificateData(pcc)
	if err != nil {
		if !signCSR && role.StoreBy == util.StoreByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error storing certificate: %s", err.Error())
		return nil, err
	}

	if !role.NoStore {
		err = b.storingCertificate(ctx, logicalRequest, pcc, parsedCertificate, role, signCSR, certId, (*reqData).commonName)
		if err != nil {
			if !signCSR && role.StoreBy == util.StoreByHASHstring {
				b.recoverBroadcast(cert, logResp, certId, err)
			}

			b.Logger().Error("error storing certificate: %s", err.Error())
			return nil, err
		}
	}

	logResp, err = b.buildLogicalResponse(pcc, parsedCertificate, role, certId, (*reqData).commonName, signCSR, (*reqData).keyPassword)
	if err != nil {
		if !signCSR && role.StoreBy == util.StoreByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error storing certificate: %s", err.Error())
		return nil, err
	}

	if !signCSR && role.StoreBy == util.StoreByHASHstring {
		b.recoverBroadcast(cert, logResp, certId, nil)
	}

	return logResp, nil
}

func (b *backend) recoverBroadcast(cert *SyncedResponse, logResp *logical.Response, certId string, err error) {
	b.mux.Lock()
	if err != nil {
		msg := "Error during enroll process. " + err.Error()
		b.Logger().Error(msg)
		cert.error = err
	}
	cert.logResponse = logResp
	b.Logger().Info(fmt.Sprintf("Launching broadcast to any waiting request for certificate hash %v", certId))
	cert.condition.Broadcast()
	b.Logger().Info(fmt.Sprintf("Removing cert from hash map. hash: %v", certId))
	delete(cache, certId)
	b.mux.Unlock()
}

func populateReqData(data *framework.FieldData, role *roleEntry) (*requestData, error) {
	var reqData requestData
	if data == nil {
		return nil, fmt.Errorf("data can't be nil")
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

	customFieldsRaw, ok := data.GetOk("custom_fields")
	if ok {
		customFields := customFieldsRaw.(string)
		customFieldsList, err := getCustomFields(customFields)
		if err != nil {
			return nil, err
		}
		reqData.customFields = *customFieldsList
	}

	if ttl, ok := data.GetOk("ttl"); ok {
		currentTTL := time.Duration(ttl.(int)) * time.Second
		// if specified role is greater than role's max ttl, then
		// role's max ttl will be used.
		if role.MaxTTL > 0 && currentTTL > role.MaxTTL {

			currentTTL = role.MaxTTL

		}
		reqData.ttl = currentTTL

	}
	return &reqData, nil
}

func createCertificateRequest(b *backend, connector *endpoint.Connector, ctx context.Context, logicRequest *logical.Request, role *roleEntry, certReq *certificate.Request) error {
	b.Logger().Info("Creating certificate request")
	err := (*connector).GenerateRequest(nil, certReq)
	if err != nil {
		return err
	}
	return nil
}

func runningEnrollRequest(b *backend, data *framework.FieldData, certReq *certificate.Request, connector endpoint.Connector, role *roleEntry, signCSR bool) (*certificate.PEMCollection, error) {
	b.Logger().Info("Running enroll request")
	format := ""
	privateKeyFormat, ok := data.GetOk("private_key_format")
	if ok {
		if privateKeyFormat == LEGACY_PEM {
			format = "legacy-pem"
		}
	}

	keyPass := fmt.Sprintf("t%d-%s.tem.pwd", time.Now().Unix(), util.RandRunes(4))
	retry, _ := data.GetOk("retry")

	var pcc *certificate.PEMCollection
	var err error
	pcc, err = issueCertificate(certReq, keyPass, connector, role, format, privateKeyFormat, signCSR)
	if err != nil {
		if retry == true {
			pcc, err = issueCertificate(certReq, keyPass, connector, role, format, privateKeyFormat, signCSR)
			if err != nil {
				return nil, err
			}
			return pcc, nil
		}
		return nil, err
	}
	return pcc, nil
}

func (b *backend) storingCertificate(ctx context.Context, logicalRequest *logical.Request, pcc *certificate.PEMCollection, parsedCertificate *ParsedCertificate, role *roleEntry, signCSR bool, certId string, commonName string) error {
	b.Logger().Info("Storing certificate")

	var err error
	var entry *logical.StorageEntry

	if role.StorePrivateKey && !signCSR {
		entry, err = logical.StorageEntryJSON("", VenafiCert{
			Certificate:      pcc.Certificate,
			CertificateChain: (*parsedCertificate).Chain,
			PrivateKey:       pcc.PrivateKey,
			SerialNumber:     (*parsedCertificate).SerialNumber,
		})
	} else {
		entry, err = logical.StorageEntryJSON("", VenafiCert{
			Certificate:      pcc.Certificate,
			CertificateChain: (*parsedCertificate).Chain,
			SerialNumber:     (*parsedCertificate).SerialNumber,
		})
	}
	if err != nil {
		return err
	}

	if role.StoreBy == util.StoreByCNString {
		// Writing certificate to the storage with CN
		certId = commonName
	} else if role.StoreBy == util.StoreByHASHstring {
		// do nothing as we already calculated the hash above
	} else {
		//Writing certificate to the storage with Serial Number
		certId = util.NormalizeSerial((*parsedCertificate).SerialNumber)
	}
	b.Logger().Info("Writing certificate to the certs/" + certId)
	entry.Key = "certs/" + certId
	if err := logicalRequest.Storage.Put(ctx, entry); err != nil {
		return fmt.Errorf("Error putting entry to storage: " + err.Error())
	}
	b.Logger().Info(fmt.Sprintf("Stored certificate with ID: %v", certId))
	return nil
}

func (b *backend) parseCertificateData(pcc *certificate.PEMCollection) (*ParsedCertificate, error) {
	var pCert ParsedCertificate
	pemBlock, _ := pem.Decode([]byte(pcc.Certificate))
	pCert.DecodedCertificate = pemBlock
	parsedCert, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		return nil, err
	}
	pCert.ParsedX509Certificate = parsedCert
	chain := strings.Join(append([]string{pcc.Certificate}, pcc.Chain...), "\n")
	pCert.Chain = chain
	b.Logger().Debug("cert Chain: " + strings.Join(pcc.Chain, ", "))
	serialNumber, err := util.GetHexFormatted(parsedCert.SerialNumber.Bytes(), ":")
	if err != nil {
		return nil, err
	}
	pCert.SerialNumber = serialNumber
	return &pCert, nil
}

func (b *backend) buildLogicalResponse(pcc *certificate.PEMCollection, parsedCertificate *ParsedCertificate, role *roleEntry, certId string, commonName string, signCSR bool, keyPassword string) (*logical.Response, error) {
	issuingCA := ""
	if len(pcc.Chain) > 0 {
		issuingCA = pcc.Chain[0]
	}

	expirationTime := (*parsedCertificate).ParsedX509Certificate.NotAfter
	expirationSec := expirationTime.Unix()

	// where "certificate_uid" is determined by "store_by" attribute defined at the role:
	// store_by = "cn" -> string conformed by -> "certificate request's common name"
	// store_by = "serial" -> string conformed by -> "generated certificate's serial"
	// store_by = "hash" -> hash string conformed by -> "Common Name + SAN DNS + Zone"
	var respData = make(map[string]interface{})

	if !role.NoStore {
		respData["certificate_uid"] = certId
	}
	respData["common_name"] = commonName
	respData["serial_number"] = (*parsedCertificate).SerialNumber
	respData["certificate_chain"] = (*parsedCertificate).Chain
	respData["certificate"] = pcc.Certificate
	respData["ca_chain"] = pcc.Chain
	respData["issuing_ca"] = issuingCA
	respData["expiration"] = expirationSec

	if !signCSR {
		if keyPassword == "" {
			respData["private_key"] = pcc.PrivateKey
		} else {
			encryptedPrivateKeyPem, err := util.EncryptPrivateKey(pcc.PrivateKey, keyPassword)
			if err != nil {
				return nil, err
			}
			respData["private_key"] = encryptedPrivateKeyPem
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
				"serial_number": (*parsedCertificate).SerialNumber,
			})
		TTL := time.Until((*parsedCertificate).ParsedX509Certificate.NotAfter)
		b.Logger().Info("Setting up secret lease duration to: " + TTL.String())
		logResp.Secret.TTL = TTL
	}
	return logResp, nil
}

func issueCertificate(certReq *certificate.Request, keyPass string, cl endpoint.Connector, role *roleEntry, format string, privateKeyFormat interface{}, signCSR bool) (pcc *certificate.PEMCollection, err error) {
	requestID, err := cl.RequestCertificate(certReq)
	if err != nil {
		return nil, err
	}

	pickupReq := &certificate.Request{
		PickupID: requestID,
		Timeout:  role.ServerTimeout,
	}

	if role.ServiceGenerated {
		pickupReq.FetchPrivateKey = true
		pickupReq.KeyPassword = keyPass
	}

	var pemCollection *certificate.PEMCollection
	pemCollection, err = cl.RetrieveCertificate(pickupReq)
	if err != nil {
		return nil, err
	}

	// Local generated
	if !signCSR && !role.ServiceGenerated {
		privateKeyPemBytes, err := certificate.GetPrivateKeyPEMBock(certReq.PrivateKey, format)
		if err != nil {
			return nil, err
		}
		privateKeyPem := string(pem.EncodeToMemory(privateKeyPemBytes))
		pemCollection.PrivateKey = privateKeyPem
	} else if role.ServiceGenerated {
		// Service generated
		if pemCollection.PrivateKey == "" {
			return nil, fmt.Errorf("we got empty private private key when we expected one to be generated from service")
		}
		privateKey, err := util.DecryptPkcs8PrivateKey(pemCollection.PrivateKey, keyPass)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(privateKey))
		if privateKeyFormat == LEGACY_PEM {
			encrypted, err := vcertutil.X509EncryptPEMBlock(
				rand.Reader, "RSA PRIVATE KEY", block.Bytes, []byte(keyPass), vcertutil.PEMCipherAES256,
			)
			if err != nil {
				return nil, err
			}
			encryptedPem := pem.EncodeToMemory(encrypted)
			privateKeyBytes, err := util.GetPrivateKey(encryptedPem, keyPass)
			if err != nil {
				return nil, err
			}
			privateKey = string(privateKeyBytes)
		}
		pemCollection.PrivateKey = privateKey
	}

	if !signCSR {
		_, err = tls.X509KeyPair([]byte(pemCollection.Certificate), []byte(pemCollection.PrivateKey))
		if err != nil {
			return nil, fmt.Errorf("the certificate returned by Venafi did not contain the requested private key," +
				" key pair has been discarded")
		}
	}
	return pemCollection, nil
}

func preventReissue(b *backend, ctx context.Context, req *logical.Request, reqData *requestData, cl *endpoint.Connector, role *roleEntry, zone string, data *framework.FieldData) *logical.Response {
	b.Logger().Info("Preventing re-issuance if certificate is already stored \nLooking if certificate exist in the platform")

	sanitizeRequestData(reqData, b.Logger())
	// creating new variables, so we don't mess up with reqData values since we may send that during request or modify them during issuing operation
	commonName := reqData.commonName
	sans := &certificate.Sans{
		DNS: reqData.altNames,
	}

	// During search, if VaaS doesn't provide the CN and the CIT restricts the CN, then we will return an error since it's not supported.
	// Getting minimum certificate time left to be considered valid
	var minCertTimeLeft time.Duration
	minCertTimeLeftRaw, ok := data.GetOk("min_cert_time_left")
	if ok {
		minCertTimeLeftInt := minCertTimeLeftRaw.(int)
		minCertTimeLeft = time.Duration(minCertTimeLeftInt) * time.Second
	} else {
		minCertTimeLeft = role.MinCertTimeLeft // should at least equals to defined default value
	}
	certInfo, err := (*cl).SearchCertificate(zone, commonName, sans, minCertTimeLeft)
	if err != nil && !(err == verror.NoCertificateFoundError || err == verror.NoCertificateWithMatchingZoneFoundError) {
		return logical.ErrorResponse(err.Error())
	}
	if certInfo != nil {
		b.Logger().Info("Looking for certificate in storage")
		serialNumber, err := util.AddSeparatorToHexFormattedString(certInfo.Serial, ":")
		if err != nil {
			return logical.ErrorResponse(err.Error())
		}
		serialNormalized := util.NormalizeSerial(serialNumber)
		b.Logger().Info("Loading certificate from storage")
		cert, err := loadCertificateFromStorage(b, ctx, req, serialNormalized, reqData.keyPassword)
		// We want to ignore error from plugin that is related to the certificate not being in storage. If it is
		// we would like to issue a new one instead
		if err != nil && !(errors.As(err, &vpkierror.CertEntryNotFound{})) {
			msg := err.Error()
			msg = "error reading venafi configuration:" + msg
			return logical.ErrorResponse(msg)
		}
		if cert != nil && cert.PrivateKey != "" {
			respData := map[string]interface{}{
				"certificate_uid":   serialNormalized,
				"serial_number":     cert.SerialNumber,
				"certificate_chain": cert.CertificateChain,
				"certificate":       cert.Certificate,
				"private_key":       cert.PrivateKey,
			}
			logResp := b.Secret(SecretCertsType).Response(
				respData,
				map[string]interface{}{
					"serial_number": serialNumber,
				})
			b.Logger().Info(fmt.Sprintf("Certificate found from local storage with cert ID %v", serialNormalized))
			return logResp
		}
		// if we arrive here it means that we could NOT find a certificate in storage, so we ignored previous error
		// and we are going to exit the prevent-reissue code block and we will try to issue a new certificate
		b.Logger().Info("Certificate not found inside storage: Issuing a new one")
		return nil
	}
	// if certInfo is equal to nil but we arrived here, means we skipped the error (since VCert returns error if certificate is not found,
	// so we won't try to open storage and we will issue a new certificate
	b.Logger().Info("No valid certificate found in local storage. Issuing a new one")
	return nil
}

func preventReissueLocal(b *backend, ctx context.Context, req *logical.Request, reqData *requestData, role *roleEntry, certId string, data *framework.FieldData) *logical.Response {
	b.Logger().Info(fmt.Sprintf("Looking for certificate in storage with hash %v", certId))
	sanitizeRequestData(reqData, b.Logger())
	venafiCert, err := loadCertificateFromStorage(b, ctx, req, certId, reqData.keyPassword)
	// We want to ignore error from plugin that is related to the certificate not being in storage. If it is
	// we would like to issue a new one instead
	if err != nil && !(errors.As(err, &vpkierror.CertEntryNotFound{})) {
		return logical.ErrorResponse(err.Error())
	}
	if venafiCert != nil && venafiCert.PrivateKey != "" {
		b.Logger().Info(fmt.Sprintf("Decrypting found certificate key pair with hash %v", certId))
		// we want to know is current certificate is about to expire
		certPem := venafiCert.Certificate
		block, _ := pem.Decode([]byte(certPem))
		cert, _ := x509.ParseCertificate(block.Bytes)
		currentTime := time.Now()
		b.Logger().Info(fmt.Sprintf("For checking certificate with hash %v, current time: %v", certId, currentTime))
		b.Logger().Info(fmt.Sprintf("For checking certificate with hash %v, current expiry date: %v", certId, cert.NotAfter))
		currentDuration := cert.NotAfter.Sub(currentTime)
		b.Logger().Info(fmt.Sprintf("For checking certificate with hash %v, current duration: %v", certId, currentDuration))
		// Getting minimum certificate time left to be considered valid
		var minCertTimeLeft time.Duration
		minCertTimeLeftRaw, ok := data.GetOk("min_cert_time_left")
		if ok {
			minCertTimeLeftInt := minCertTimeLeftRaw.(int)
			minCertTimeLeft = time.Duration(minCertTimeLeftInt) * time.Second
		} else {
			minCertTimeLeft = role.MinCertTimeLeft
		}

		b.Logger().Info(fmt.Sprintf("For checking certificate with hash %v, current set duration: %v", certId, minCertTimeLeft))
		if currentDuration > minCertTimeLeft {
			respData := map[string]interface{}{
				"certificate_uid":   certId,
				"serial_number":     venafiCert.SerialNumber,
				"certificate_chain": venafiCert.CertificateChain,
				"certificate":       venafiCert.Certificate,
				"private_key":       venafiCert.PrivateKey,
			}
			var logResp *logical.Response
			serialNumber, err := util.AddSeparatorToHexFormattedString(venafiCert.SerialNumber, ":")
			if err != nil {
				return logical.ErrorResponse(err.Error())
			}
			logResp = b.Secret(SecretCertsType).Response(
				respData,
				map[string]interface{}{
					"serial_number": serialNumber,
				})
			b.Logger().Info(fmt.Sprintf("Certificate found from local storage with hash %v", certId))
			return logResp
		}
		msg := fmt.Sprintf("certificate key pair with hash %v is about to expire:\n", certId)
		msg = msg + fmt.Sprintf("current time: %v\n", currentTime)
		msg = msg + fmt.Sprintf("certitficate expiry date: %v\n", cert.NotAfter)
		msg = msg + fmt.Sprintf("current duration: %v\n", currentDuration)
		msg = msg + fmt.Sprintf("set duration: %v\n", minCertTimeLeft)
		b.Logger().Info(msg)
		return nil
	}
	// if we were not able to find a certificate or certificate is not valid (about to expire or expired), we let issuance occur.
	b.Logger().Info(fmt.Sprintf("certificate key pair with hash %v not found inside local storage", certId))
	return nil
}

func formRequest(reqData requestData, role *roleEntry, cl *endpoint.Connector, signCSR bool, logger hclog.Logger) (certReq *certificate.Request, err error) {
	if !signCSR {
		msg := "forming certificate request with "
		if reqData.commonName != "" {
			msg = msg + fmt.Sprintf("CN: %s", reqData.commonName)
		}
		if len(reqData.altNames) > 0 {
			if reqData.commonName != "" {
				msg = msg + " " // leaving space if previously common name existed
			}
			msg = msg + "SAN DNS: "
			for index, altName := range reqData.altNames {
				msg = msg + altName
				if index != len(reqData.altNames)-1 {
					msg = msg + ", "
				}
			}
		}
		logger.Info(msg)
		if len(reqData.altNames) == 0 && reqData.commonName == "" {
			return certReq, fmt.Errorf("no domains specified on certificate")
		}
		sanitizeRequestData(&reqData, logger)

		certReq = &certificate.Request{
			CsrOrigin:   certificate.LocalGeneratedCSR,
			KeyPassword: reqData.keyPassword,
		}

		if reqData.commonName != "" {
			certReq.Subject = pkix.Name{
				CommonName: reqData.commonName,
			}
		}

		if len(reqData.commonName) == 0 && len(reqData.altNames) > 0 && (*cl).GetType() == endpoint.ConnectorTypeTPP {
			certReq.FriendlyName = reqData.altNames[0]
		}

		if role.ServiceGenerated {
			certReq.CsrOrigin = certificate.ServiceGeneratedCSR
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
		logger.Info("Signing user provided CSR")

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

func getIssuerHint(is string) vcertutil.IssuerHint {

	var issuerHint vcertutil.IssuerHint

	if is != "" {

		issuerOpt := string(is[0])
		issuerOpt = strings.ToLower(issuerOpt)

		switch issuerOpt {

		case "m":
			issuerHint = vcertutil.IssuerHintMicrosoft
		case "d":
			issuerHint = vcertutil.IssuerHintDigicert
		case "e":
			issuerHint = vcertutil.IssuerHintEntrust
		}

	}

	return issuerHint

}

func getCustomFields(customFields string) (*[]string, error) {
	var resultingCustomFields []string
	regex, err := regexp.Compile("^([^=]+=[^=]+)$")
	if err != nil {
		return nil, err
	}
	msg := "invalid custom fields; must be 'key=value' using commas to separate multiple key-value pairs." +
		"If you want to provide a comma in a custom field that is type string a long with other custom fields," +
		"you can provide as follows:" +
		"\"\nkey=\"value1,value2\",key2=value3\" or \"'key=value1,value2',key2=value\"\n"

	auxSplit := strings.Split(customFields, ",")
	singleQuoteStringWithCommas := ""
	doubleQuotesStringWithCommas := ""
	for index, data := range auxSplit {

		// we are looking for inner single quote string
		if strings.HasPrefix(data, singleQuote) {
			if doubleQuotesStringWithCommas != "" {
				return nil, fmt.Errorf("bad formatted string, already filling double quotes value. Invalid string: %s", customFields)
			}
			if strings.HasPrefix(singleQuoteStringWithCommas, singleQuote) && singleQuoteStringWithCommas != "" {
				return nil, fmt.Errorf("bad formatted string, encountered leading single quote in an already filled value. Invalid string: %s", customFields)
			}
			if len(auxSplit)-1 == index {
				// means we couldn't find the closing single quote
				return nil, fmt.Errorf("bad formatted string, couldn't find closing single quote. Invalid string: %s", customFields)
			}
			singleQuoteStringWithCommas = singleQuoteStringWithCommas + data + ","
			continue
		}
		// we are looking for inner double comma string
		if strings.HasPrefix(data, doubleQuotes) {
			if singleQuoteStringWithCommas != "" {
				return nil, fmt.Errorf("bad formatted string, already filling single quote value. Invalid string: %s", customFields)
			}
			if strings.HasPrefix(doubleQuotesStringWithCommas, doubleQuotes) && doubleQuotesStringWithCommas != "" {
				return nil, fmt.Errorf("bad formatted string, encountered leading double quotes in an already filled value. Invalid string: %s", customFields)
			}
			if len(auxSplit)-1 == index {
				// means we couldn't find the closing double quotes
				return nil, fmt.Errorf("bad formatted string, couldn't find closing double quotes. Invalid string: %s", customFields)
			}
			doubleQuotesStringWithCommas = doubleQuotesStringWithCommas + data + ","
			continue
		}
		// we are looking for inner single quote string
		if singleQuoteStringWithCommas != "" {
			if doubleQuotesStringWithCommas != "" {
				return nil, fmt.Errorf("bad formatted string, already filling double quotes value. Invalid string: %s", customFields)
			}
			if len(auxSplit)-1 == index && !strings.HasSuffix(data, singleQuote) {
				// means we couldn't find the closing single quote
				return nil, fmt.Errorf("bad formatted string, couldn't find closing single quote. Invalid string: %s", customFields)
			}
			if strings.HasSuffix(data, singleQuote) {
				singleQuoteStringWithCommas = singleQuoteStringWithCommas + data
				if !regex.MatchString(singleQuoteStringWithCommas) {
					return nil, fmt.Errorf(msg)
				}
				resultingCustomFields = append(resultingCustomFields, strings.Trim(singleQuoteStringWithCommas, singleQuote))

				singleQuoteStringWithCommas = "" // we clean
				continue
			}
			singleQuoteStringWithCommas = singleQuoteStringWithCommas + data + ","
			continue
		}
		// we are looking for inner double comma string
		if doubleQuotesStringWithCommas != "" {
			if singleQuoteStringWithCommas != "" {
				return nil, fmt.Errorf("bad formatted string, already filling single quote value. Invalid string: %s", customFields)
			}
			if len(auxSplit)-1 == index && !strings.HasSuffix(data, doubleQuotes) {
				// means we couldn't find the closing single quote
				return nil, fmt.Errorf("bad formatted string, couldn't find closing double quotes. Invalid string: %s", customFields)
			}
			if strings.HasSuffix(data, doubleQuotes) {
				doubleQuotesStringWithCommas = doubleQuotesStringWithCommas + data
				if !regex.MatchString(doubleQuotesStringWithCommas) {
					return nil, fmt.Errorf(msg)
				}
				resultingCustomFields = append(resultingCustomFields, strings.Trim(doubleQuotesStringWithCommas, doubleQuotes))

				doubleQuotesStringWithCommas = "" // we clean
				continue
			}
			doubleQuotesStringWithCommas = doubleQuotesStringWithCommas + data + ","
			continue
		}
		// if we are not looking for string inside our string, then we validate regex normally against data
		if !regex.MatchString(data) {
			return nil, fmt.Errorf(msg)
		}
		resultingCustomFields = append(resultingCustomFields, data)
	}
	return &resultingCustomFields, nil
}

func getCertIdHash(reqData requestData, zone string, logger hclog.Logger) string {
	logger.Debug("Creating hash for certificate ID")
	s := ""
	if reqData.commonName != "" {
		s = s + reqData.commonName + ";"
	}

	// unless it's a common name, we want the sans to be separated by comma
	if len(reqData.altNames) > 0 {
		orderSANDNS(&reqData, logger)
		for index, altName := range reqData.altNames {
			if index == len(reqData.altNames)-1 {
				s = s + altName
			}
			s = s + altName + ","
		}
	}

	s = s + ";" + zone

	s = util.Sha1sum(s)
	return s
}

func addCNtoDNSList(reqData *requestData, logger hclog.Logger) {
	if !util.SliceContains(reqData.altNames, reqData.commonName) && reqData.commonName != "" { // Go can compare if en empty string exist in the slice, so we omit that case
		logger.Info(fmt.Sprintf("Adding CN %s to SAN %s because it wasn't included.", reqData.commonName, reqData.altNames))
		reqData.altNames = append(reqData.altNames, reqData.commonName)
	}
}

func removeDuplicateSANDNS(reqData *requestData, logger hclog.Logger) {
	logger.Info("Removing duplicate SAN DNS from request data")
	altNames := &reqData.altNames
	util.RemoveDuplicateStr(altNames)
}

func orderSANDNS(reqData *requestData, logger hclog.Logger) {
	logger.Info("ordering SAN DNS")
	sort.Strings(reqData.altNames)
}

func sanitizeRequestData(reqData *requestData, logger hclog.Logger) {
	logger.Info("Sanitizing request data")
	removeDuplicateSANDNS(reqData, logger)
	addCNtoDNSList(reqData, logger)
	orderSANDNS(reqData, logger)
}

func validateAccessToken(b *backend, ctx context.Context, connector endpoint.Connector, cfg *vcert.Config, logReq *logical.Request, role *roleEntry) (endpoint.Connector, error) {

	refreshNeeded, _, err := isTokenRefreshNeeded(b, ctx, logReq.Storage, role.VenafiSecret)
	if err != nil {
		return nil, err
	}
	if refreshNeeded {
		if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby | consts.ReplicationPerformanceSecondary) {
			// only the leader can handle token refreshing, we don't ever want to enter into refreshing process if we are
			// getting request in vault follower node
			return nil, logical.ErrReadOnly
		}
		b.Logger().Info("Token refresh is needed")
		if err != nil {
			return nil, err
		}
		b.Logger().Info("Updating access_token")
		err = updateAccessToken(b, ctx, logReq, cfg, role)
		if err != nil {
			return nil, err
		}
		b.Logger().Info("Successfully updated tokens. Refreshing the connector with new token")
		var newConnector endpoint.Connector
		newConnector, cfg, err = b.ClientVenafi(ctx, logReq, role)
		if err != nil {
			b.Logger().Error(fmt.Sprintf("got error when getting new connector: %s", err.Error()))
			return nil, err
		}
		connector = newConnector
	}
	b.Logger().Info("Successfully updated connector with new token")
	return connector, nil
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

type VenafiCert struct {
	Certificate      string `json:"certificate"`
	CertificateChain string `json:"certificate_chain"`
	PrivateKey       string `json:"private_key"`
	SerialNumber     string `json:"serial_number"`
}

type ParsedCertificate struct {
	DecodedCertificate    *pem.Block
	ParsedX509Certificate *x509.Certificate
	Chain                 string
	SerialNumber          string
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
	singleQuote  = "'"
	doubleQuotes = "\""
)
