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
	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki/vpkierror"
	"github.com/Venafi/vcert/v4/pkg/endpoint"
	"github.com/Venafi/vcert/v4/pkg/util"
	"github.com/Venafi/vcert/v4/pkg/verror"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"net"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/Venafi/vcert/v4/pkg/certificate"
	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
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
				Type:        framework.TypeCommaStringSlice,
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
		b.Logger().Error("error creating Venafi connector: %s", err.Error())
		return nil, err
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
	if !role.NoStore && role.StoreBy == storeByHASHstring && !signCSR {
		certId = getCertIdHash(*reqData, cfg.Zone, b.Logger())
	}

	if !role.IgnoreLocalStorage && role.StorePrivateKey && role.StoreBy == storeBySerialString && !signCSR {
		// if we don't receive a logic response, whenever is an error or the actual certificate found in storage
		// means we need to issue a new one
		logicalResp := preventReissue(b, ctx, logicalRequest, reqData, &connector, role, cfg.Zone)
		if logicalResp != nil {
			return logicalResp, nil
		}
	} else if !role.IgnoreLocalStorage && role.StorePrivateKey && role.StoreBy == storeByHASHstring && !signCSR {
		b.Logger().Info(fmt.Sprintf("Calling prevent local for hash %v", certId))
		logicalResp := preventReissueLocal(b, ctx, logicalRequest, reqData, role, certId)
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
	if !signCSR && role.StoreBy == storeByHASHstring {
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
		if !signCSR && role.StoreBy == storeByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error error forming request: %s", err.Error())
		return logical.ErrorResponse(err.Error()), nil
	}

	err = createCertificateRequest(b, &connector, ctx, logicalRequest, role, certReq)
	if err != nil {
		if !signCSR && role.StoreBy == storeByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error creating certificate request: %s", err.Error())
		return nil, err
	}
	var pcc *certificate.PEMCollection
	pcc, err = runningEnrollRequest(b, data, certReq, connector, role, signCSR)
	if err != nil {
		if !signCSR && role.StoreBy == storeByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error running enroll request: %s", err.Error())
		return nil, err
	}

	logResp, err = b.storingCertificate(ctx, logicalRequest, pcc, role, signCSR, certId, (*reqData).commonName, (*reqData).keyPassword)
	if err != nil {
		if !signCSR && role.StoreBy == storeByHASHstring {
			b.recoverBroadcast(cert, logResp, certId, err)
		}
		b.Logger().Error("error storing certificate: %s", err.Error())
		return nil, err
	}

	if !signCSR && role.StoreBy == storeByHASHstring {
		b.recoverBroadcast(cert, logResp, certId, nil)
	}

	return logResp, nil
}

func (b *backend) recoverBroadcast(cert *SyncedResponse, logResp *logical.Response, certId string, err error) {

	b.mux.Lock()
	msg := fmt.Sprintf("Launching broadcast to any waiting request for certificate hash %v", certId)
	if err != nil {
		msg = "Error enrolling certificate. " + msg
		cert.error = err
		cert.logResponse = nil
	}
	b.Logger().Debug(msg)
	cert.logResponse = logResp
	cert.condition.Broadcast()
	msg = fmt.Sprintf("Removing cert from hash map. hash: %v", certId)
	if err != nil {
		msg = "Error enrolling certificate. " + msg
		cert.error = err
		cert.logResponse = nil
	}
	b.Logger().Debug(msg)
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

	customFields, ok := data.GetOk("custom_fields")
	if ok {
		reqData.customFields = customFields.([]string)
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
	if (err != nil) && ((*connector).GetType() == endpoint.ConnectorTypeTPP) {
		msg := err.Error()

		// catch the scenario when token is expired and deleted.
		var regex = regexp.MustCompile("(expired|invalid)_token")

		// validate if the error is related to an expired access token, at this moment the only way can validate this is using the error message
		// and verify if that message describes errors related to expired access token.
		code := getStatusCode(msg)
		if code == HTTP_UNAUTHORIZED && regex.MatchString(msg) {
			cfg, err := b.getConfig(ctx, logicRequest, role, true)

			if err != nil {
				return err
			}

			if cfg.Credentials.RefreshToken != "" {
				err = updateAccessToken(cfg, b, ctx, logicRequest, role.Name)

				if err != nil {
					return err
				}

				// everything went fine so get the new client with the new refreshed access token
				var newConnector endpoint.Connector
				newConnector, _, err = b.ClientVenafi(ctx, logicRequest, role)
				if err != nil {
					return err
				}
				connector = &newConnector

				b.Logger().Debug("Making certificate request again")

				err = (*connector).GenerateRequest(nil, certReq)
				if err != nil {
					return err
				}
			} else {
				return fmt.Errorf("access token is expired. Tried to get new access token, but refresh token is empty")
			}
		} else {
			return err
		}
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

	keyPass := fmt.Sprintf("t%d-%s.tem.pwd", time.Now().Unix(), randRunes(4))
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

func (b *backend) storingCertificate(ctx context.Context, logicalRequest *logical.Request, pcc *certificate.PEMCollection, role *roleEntry, signCSR bool, certId string, commonName string, keyPassword string) (*logical.Response, error) {
	b.Logger().Info("Storing certificate")
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
	b.Logger().Debug("cert Chain: " + strings.Join(pcc.Chain, ", "))

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

	if !role.NoStore {
		if role.StoreBy == storeByCNString {
			// Writing certificate to the storage with CN
			certId = commonName
		} else if role.StoreBy == storeByHASHstring {
			// do nothing as we already calculated the hash above
		} else {
			//Writing certificate to the storage with Serial Number
			certId = normalizeSerial(serialNumber)
		}
		b.Logger().Info("Writing certificate to the certs/" + certId)
		entry.Key = "certs/" + certId
		if err := logicalRequest.Storage.Put(ctx, entry); err != nil {
			return nil, fmt.Errorf("Error putting entry to storage: " + err.Error())
		}
		b.Logger().Info(fmt.Sprintf("Stored certificate with ID: %v", certId))
	}

	issuingCA := ""
	if len(pcc.Chain) > 0 {
		issuingCA = pcc.Chain[0]
	}

	expirationTime := parsedCertificate.NotAfter
	expirationSec := expirationTime.Unix()

	// where "certificate_uid" is determined by "store_by" attribute defined at the role:
	// store_by = "cn" -> string conformed by -> "certificate request's common name"
	// store_by = "serial" -> string conformed by -> "generated certificate's serial"
	// store_by = "hash" -> hash string conformed by -> "Common Name + SAN DNS + Zone"
	respData := map[string]interface{}{
		"certificate_uid":   certId,
		"common_name":       commonName,
		"serial_number":     serialNumber,
		"certificate_chain": chain,
		"certificate":       pcc.Certificate,
		"ca_chain":          pcc.Chain,
		"issuing_ca":        issuingCA,
		"expiration":        expirationSec,
	}

	if !signCSR {
		if keyPassword == "" {
			respData["private_key"] = pcc.PrivateKey
		} else {
			encryptedPrivateKeyPem, err := encryptPrivateKey(pcc.PrivateKey, keyPassword)
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
				"serial_number": serialNumber,
			})
		TTL := time.Until(parsedCertificate.NotAfter)
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
		privateKey, err := DecryptPkcs8PrivateKey(pemCollection.PrivateKey, keyPass)
		if err != nil {
			return nil, err
		}
		block, _ := pem.Decode([]byte(privateKey))
		if privateKeyFormat == LEGACY_PEM {
			encrypted, err := util.X509EncryptPEMBlock(
				rand.Reader, "RSA PRIVATE KEY", block.Bytes, []byte(keyPass), util.PEMCipherAES256,
			)
			if err != nil {
				return nil, err
			}
			encryptedPem := pem.EncodeToMemory(encrypted)
			privateKeyBytes, err := getPrivateKey(encryptedPem, keyPass)
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

func preventReissue(b *backend, ctx context.Context, req *logical.Request, reqData *requestData, cl *endpoint.Connector, role *roleEntry, zone string) *logical.Response {
	b.Logger().Info("Preventing re-issuance if certificate is already stored \nLooking if certificate exist in the platform")

	sanitizeRequestData(reqData, b.Logger())
	// creating new variables, so we don't mess up with reqData values since we may send that during request or modify them during issuing operation
	commonName := reqData.commonName
	sans := &certificate.Sans{
		DNS: reqData.altNames,
	}

	// During search, if VaaS doesn't provide the CN and the CIT restricts the CN, then we will return an error since it's not supported.
	certInfo, err := (*cl).SearchCertificate(zone, commonName, sans, role.MinCertTimeLeft)
	if err != nil && !(err == verror.NoCertificateFoundError || err == verror.NoCertificateWithMatchingZoneFoundError) {
		return logical.ErrorResponse(err.Error())
	}
	if certInfo != nil {
		b.Logger().Info("Looking for certificate in storage")
		serialNumber, err := addSeparatorToHexFormattedString(certInfo.Serial, ":")
		if err != nil {
			return logical.ErrorResponse(err.Error())
		}
		serialNormalized := normalizeSerial(serialNumber)
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
	b.Logger().Info(fmt.Sprintf("Not valid certificate found in Plataform %v: Issuing a new one", (*cl).GetType()))
	return nil
}

func preventReissueLocal(b *backend, ctx context.Context, req *logical.Request, reqData *requestData, role *roleEntry, certId string) *logical.Response {
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
		roleDuration := role.MinCertTimeLeft
		b.Logger().Info(fmt.Sprintf("For checking certificate with hash %v, current role duration: %v", certId, roleDuration))
		if currentDuration > roleDuration {
			respData := map[string]interface{}{
				"certificate_uid":   certId,
				"serial_number":     venafiCert.SerialNumber,
				"certificate_chain": venafiCert.CertificateChain,
				"certificate":       venafiCert.Certificate,
				"private_key":       venafiCert.PrivateKey,
			}
			var logResp *logical.Response
			serialNumber, err := addSeparatorToHexFormattedString(venafiCert.SerialNumber, ":")
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
		msg = msg + fmt.Sprintf("role duration: %v\n", roleDuration)
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

	s = sha1sum(s)
	return s
}

func addCNtoDNSList(reqData *requestData, logger hclog.Logger) {
	if !sliceContains(reqData.altNames, reqData.commonName) && reqData.commonName != "" { // Go can compare if en empty string exist in the slice, so we omit that case
		logger.Info(fmt.Sprintf("Adding CN %s to SAN %s because it wasn't included.", reqData.commonName, reqData.altNames))
		reqData.altNames = append(reqData.altNames, reqData.commonName)
	}
}

func removeDuplicateSANDNS(reqData *requestData, logger hclog.Logger) {
	logger.Info("Removing duplicate SAN DNS from request data")
	altNames := &reqData.altNames
	removeDuplicateStr(altNames)
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
