package pki

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/helper/consts"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

// ngtsScopeRegex anchors the NGTS scope format (tsg_id:<10 digits>), stricter than the
// Go SDK's unanchored check — matching the vcert-python behavior.
var ngtsScopeRegex = regexp.MustCompile(util.NgtsScopePattern)

func pathCredentialsList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: util.CredentialsRootPath + "?$",
		Fields:  nil,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretList,
				Summary:  "List all CyberArk secrets",
			},
		},
		HelpSynopsis:    pathListVenafiSecretsHelpSyn,
		HelpDescription: pathListVenafiSecretsHelpDesc,
	}
}

func pathCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: util.CredentialsRootPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the authentication object",
				Required:    true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Certificate Manager, Self-Hosted policy or Certificate Manager, SaaS project zone. 
Example for Certificate Manager, Self-Hosted: testpolicy\\vault
Example for Certificate Manager, SaaS: e33f3e40-4e7e-11ea-8da3-b3c196ebeb0b`,
				Required: true,
			},
			"tpp_url": {
				Type:        framework.TypeString,
				Description: `URL of Certificate Manager, Self-Hosted. Example: https://tpp.venafi.example/vedsdk. Deprecated, use 'url' instead`,
				Deprecated:  true,
			},
			"url": {
				Type:        framework.TypeString,
				Description: `URL of CyberArk API Endpoint. Example: https://tpp.venafi.example`,
				Required:    true,
			},

			"cloud_url": {
				Type:        framework.TypeString,
				Description: `URL for Certificate Manager, SaaS. Set it only if you want to use non production Cloud. Deprecated, use 'url' instead`,
				Deprecated:  true,
			},
			"tpp_user": {
				Type:        framework.TypeString,
				Description: `WebSDK username for Certificate Manager, Self-Hosted API`,
				Deprecated:  true,
			},
			"tpp_password": {
				Type:        framework.TypeString,
				Description: `Password for WebSDK user`,
				Deprecated:  true,
			},
			"access_token": {
				Type:        framework.TypeString,
				Description: `Access token for Certificate Manager, Self-Hosted; omit if secrets engine should manage token refreshes`,
			},
			"refresh_token": {
				Type:        framework.TypeString,
				Description: `Primary refresh token for updating Certificate Manager, Self-Hosted access token before it expires`,
			},
			"refresh_token_2": {
				Type:        framework.TypeString,
				Description: `Secondary refresh token for ensuring no impact on certificate requests when tokens are refreshed`,
			},
			"refresh_interval": {
				Type:        framework.TypeDurationSecond,
				Description: `Frequency at which secrets engine should refresh tokens.`,
				Default:     time.Duration(30*24) * time.Hour,
			},
			"apikey": {
				Type:        framework.TypeString,
				Description: `API key for Certificate Manager, SaaS. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
			},
			"trust_bundle_file": {
				Type: framework.TypeString,
				Description: `Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.
Example: trust_bundle_file="/path-to/bundle.pem""`,
			},
			"fakemode": {
				Type:        framework.TypeBool,
				Description: `Set it to true to use fake CA instead of Certificate Manager, Self-Hosted or Certificate Manager, SaaS to issue certificates. Useful for testing.`,
				Default:     false,
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: `Use to specify the application that will be using the token.`,
				Default:     `hashicorp-vault-by-venafi`,
			},
			"ngts_token_url": {
				Type:        framework.TypeString,
				Description: `Strata Cloud Manager (NGTS) OAuth2 token endpoint for service-account authentication. Must be an https:// URL within ` + util.NgtsTrustedTokenHostSuffix,
			},
			"ngts_client_id": {
				Type:        framework.TypeString,
				Description: `Strata Cloud Manager (NGTS) service-account client id.`,
			},
			"ngts_client_secret": {
				Type:        framework.TypeString,
				Description: `Strata Cloud Manager (NGTS) service-account client secret.`,
			},
			"ngts_scope": {
				Type:        framework.TypeString,
				Description: `Strata Cloud Manager (NGTS) OAuth2 scope, in the form tsg_id:<10-digit TSG ID>.`,
			},
			"ngts_access_token": {
				Type:        framework.TypeString,
				Description: `Pre-issued Strata Cloud Manager (NGTS) bearer token; alternative to the ngts_client_id/ngts_client_secret service account.`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretRead,
				Summary:  "Read the properties of a CyberArk secret and displays it to the user.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretCreate,
				Summary:  "Create a CyberArk secret",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretDelete,
				Summary:  "Delete a CyberArk secret",
			},
		},
		HelpSynopsis:    pathVenafiSecretsHelpSyn,
		HelpDescription: pathVenafiSecretsHelpDesc,
	}
}

func (b *backend) pathVenafiSecretList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, util.CredentialsRootPath)
	if err != nil {
		return nil, err
	}

	return logical.ListResponse(entries), nil
}

func (b *backend) pathVenafiSecretRead(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	policyName := data.Get("name").(string)
	if policyName == "" {
		return logical.ErrorResponse("missing policy name"), nil
	}

	cred, err := b.getVenafiSecret(ctx, req.Storage, policyName)
	if err != nil {
		return nil, err
	}
	if cred == nil {
		return nil, nil
	}
	resp := &logical.Response{
		Data: cred.ToResponseData(),
	}

	return resp, nil
}

func (b *backend) pathVenafiSecretDelete(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {

	if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby | consts.ReplicationPerformanceSecondary) {
		// only the leader can handle deletion
		return nil, logical.ErrReadOnly
	}
	err := req.Storage.Delete(ctx, util.CredentialsRootPath+data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathVenafiSecretCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	if b.System().ReplicationState().HasState(consts.ReplicationPerformanceStandby | consts.ReplicationPerformanceSecondary) {
		// only the leader can handle token creating, we don't ever want to enter into refreshing process if we are
		// getting request in vault follower node
		return nil, logical.ErrReadOnly
	}
	var err error
	name := data.Get("name").(string)
	b.Logger().Info(fmt.Sprintf("Creating CyberArk secret: %s", name))
	url := data.Get("url").(string)
	var tppUrl, cloudUrl string

	if url == "" {
		tppUrl = data.Get("tpp_url").(string)
		url = tppUrl
	}
	if url == "" {
		cloudUrl = data.Get("cloud_url").(string)
		url = cloudUrl
	}

	entry := &venafiSecretEntry{
		URL:              url,
		Zone:             data.Get("zone").(string),
		TppURL:           tppUrl,
		TppUser:          data.Get("tpp_user").(string),
		TppPassword:      data.Get("tpp_password").(string),
		AccessToken:      data.Get("access_token").(string),
		RefreshToken:     data.Get("refresh_token").(string),
		RefreshToken2:    data.Get("refresh_token_2").(string),
		RefreshInterval:  time.Duration(data.Get("refresh_interval").(int)) * time.Second,
		NextRefresh:      time.Now(),
		CloudURL:         cloudUrl,
		Apikey:           data.Get("apikey").(string),
		TrustBundleFile:  data.Get("trust_bundle_file").(string),
		Fakemode:         data.Get("fakemode").(bool),
		ClientId:         data.Get("client_id").(string),
		NgtsTokenURL:     data.Get("ngts_token_url").(string),
		NgtsClientId:     data.Get("ngts_client_id").(string),
		NgtsClientSecret: data.Get("ngts_client_secret").(string),
		NgtsScope:        data.Get("ngts_scope").(string),
		NgtsAccessToken:  data.Get("ngts_access_token").(string),
	}

	b.Logger().Info(fmt.Sprintf("Validating data for CyberArk secret %s", name))
	err = validateVenafiSecretEntry(entry)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("Error with CyberArk secret data: %s", err.Error()))
		return logical.ErrorResponse(err.Error()), nil
	}

	// Harden the NGTS token URL (credential sink) at create time, so the stored value is
	// already https:// and within the trusted Palo Alto domain and is reused on every issue.
	// Only applies to service-account auth (skipped for a pre-issued ngts_access_token).
	var ngtsWarnings []string
	if entry.isNgts() && entry.NgtsAccessToken == "" {
		normalized, warns, nErr := normalizeNgtsTokenURL(entry.NgtsTokenURL)
		if nErr != nil {
			b.Logger().Error(fmt.Sprintf("Error with NGTS token URL: %s", nErr.Error()))
			return logical.ErrorResponse(nErr.Error()), nil
		}
		entry.NgtsTokenURL = normalized
		ngtsWarnings = warns
	}
	if entry.RefreshToken != "" && !entry.Fakemode {
		b.Logger().Info("Refresh tokens are provided. Setting up data")
		for i := 0; i < 2; i++ {

			b.Logger().Info("creating config for refreshing tokens")
			cfg, err := createConfigFromFieldData(entry)
			if err != nil {
				b.Logger().Error(fmt.Sprintf("Error during CyberArk secret creation: creating config error: %s", err.Error()))
				return logical.ErrorResponse(err.Error()), nil
			}

			b.Logger().Info("Refreshing tokens during CyberArk secret creation")
			tokenInfo, err := getAccessData(cfg)
			if err != nil {
				b.Logger().Error(fmt.Sprintf("Error during CyberArk secret creation: refreshing tokens error: %s", err.Error()))
				return logical.ErrorResponse(err.Error()), nil
			}

			if i == 0 && tokenInfo.Refresh_token != "" {
				// ensure refresh interval is proactive by not allowing it to be longer than access token is valid
				maxInterval := time.Until(time.Unix(int64(tokenInfo.Expires), 0)).Round(time.Minute) - time.Duration(30)*time.Second
				if maxInterval < entry.RefreshInterval {
					b.Logger().Info("Refresh interval is not correct since is longer than access token validity. Setting up a proper one")
					entry.RefreshInterval = maxInterval
				}

				entry.RefreshToken = entry.RefreshToken2
				entry.RefreshToken2 = tokenInfo.Refresh_token
				entry.NextRefresh = time.Now().Add(entry.RefreshInterval)
			}

			if i > 0 {
				if tokenInfo.Access_token != "" {
					entry.AccessToken = tokenInfo.Access_token
				}
				if tokenInfo.Refresh_token != "" {
					entry.RefreshToken = tokenInfo.Refresh_token
				}
			}
		}
		b.Logger().Info("Success setting up refresh token data of CyberArk secret")
	}

	//Store it

	b.Logger().Info("Setting up data for entry of CyberArk secret")
	jsonEntry, err := logical.StorageEntryJSON(util.CredentialsRootPath+name, entry)

	if err != nil {
		b.Logger().Error(fmt.Sprintf("Error during CyberArk secret creation: error setting up refresh tokens for storage: %s", err.Error()))
		return nil, err
	}

	b.Logger().Info("Storing entry of CyberArk secret")
	err = req.Storage.Put(ctx, jsonEntry)
	if err != nil {
		b.Logger().Error(fmt.Sprintf("Error during CyberArk secret creation: error storing refresh tokens: %s", err.Error()))
		return nil, err
	}

	var logResp *logical.Response

	warnings := append(ngtsWarnings, getWarnings(entry, name)...)

	if cap(warnings) > 0 {
		logResp = &logical.Response{

			Data:     map[string]interface{}{},
			Redirect: "",
			Warnings: warnings,
		}
		b.Logger().Info(fmt.Sprintf("Sucess on creating CyberArk secret %s (with warnings)", name))
		return logResp, nil
	}
	b.Logger().Info(fmt.Sprintf("Sucess on creating CyberArk secret %s", name))
	return nil, nil
}

func (b *backend) getVenafiSecret(ctx context.Context, s logical.Storage, name string) (*venafiSecretEntry, error) {
	entry, err := s.Get(ctx, util.CredentialsRootPath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result venafiSecretEntry
	err = entry.DecodeJSON(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func validateVenafiSecretEntry(entry *venafiSecretEntry) error {
	if !entry.Fakemode && entry.Apikey == "" && (entry.TppUser == "" || entry.TppPassword == "") && entry.RefreshToken == "" && entry.AccessToken == "" && !entry.isNgts() {
		return errors.New(util.ErrorTextInvalidMode)
	}

	//Only validate other fields if mode is not fakemode
	if !entry.Fakemode {
		// NGTS may omit url (the SDK default host is production-correct at v5.13.7), so the
		// url-required check is skipped for NGTS — but zone is still required (validated below).
		if entry.URL == "" && entry.Apikey == "" && !entry.isNgts() {
			return errors.New(util.ErrorTextURLEmpty)
		}

		if entry.Zone == "" {
			return errors.New(util.ErrorTextZoneEmpty)
		}

		// NGTS must not be combined with any other backend's credentials.
		if entry.isNgts() {
			if entry.TppUser != "" || entry.TppPassword != "" {
				return errors.New(util.ErrorTextMixedNgtsAndTPP)
			}
			if entry.AccessToken != "" || entry.RefreshToken != "" {
				return errors.New(util.ErrorTextMixedNgtsAndToken)
			}
			if entry.Apikey != "" {
				return errors.New(util.ErrorTextMixedNgtsAndCloud)
			}
			return validateNgtsSecretEntry(entry)
		}

		if entry.TppUser != "" && entry.Apikey != "" {
			return errors.New(util.ErrorTextMixedTPPAndCloud)
		}

		if entry.TppUser != "" && entry.AccessToken != "" {
			return errors.New(util.ErrorTextMixedTPPAndToken)
		}

		if entry.AccessToken != "" && entry.Apikey != "" {
			return errors.New(util.ErrorTextMixedTokenAndCloud)
		}

		if (entry.RefreshToken != "" && entry.RefreshToken2 == "") || (entry.RefreshToken == "" && entry.RefreshToken2 != "") {
			return errors.New(util.ErrorTextNeed2RefreshTokens)
		}
	}
	return nil
}

// validateNgtsSecretEntry validates an NGTS secret: either a complete service-account
// 4-tuple (client_id + client_secret + token_url + scope) or a pre-issued access token.
// Token-URL host/scheme hardening happens separately in normalizeNgtsTokenURL at create time.
func validateNgtsSecretEntry(entry *venafiSecretEntry) error {
	if entry.NgtsAccessToken != "" {
		return nil
	}

	if entry.NgtsClientId == "" || entry.NgtsClientSecret == "" {
		return errors.New(util.ErrorTextNgtsCredsIncomplete)
	}
	if entry.NgtsTokenURL == "" {
		return errors.New(util.ErrorTextNgtsTokenURLEmpty)
	}
	if !ngtsScopeRegex.MatchString(entry.NgtsScope) {
		return errors.New(util.ErrorTextNgtsScopeInvalid)
	}
	return nil
}

// normalizeNgtsTokenURL hardens the NGTS token endpoint, which receives the service-account
// client_id/client_secret via HTTP Basic auth (the Go SDK applies no scheme/host checks):
//  1. coerce http:// -> https:// (with a warning), default a scheme-less value to https://;
//  2. reject (fail-closed) any host outside the trusted Palo Alto domain.
//
// Empty input is left to validateNgtsSecretEntry, which requires a token URL in service-account mode.
func normalizeNgtsTokenURL(raw string) (string, []string, error) {
	trimmed := strings.TrimSpace(raw)
	if trimmed == "" {
		return "", nil, nil
	}

	var warnings []string
	lower := strings.ToLower(trimmed)
	switch {
	case strings.HasPrefix(lower, "http://"):
		trimmed = "https://" + trimmed[len("http://"):]
		warnings = append(warnings, util.WarningNgtsTokenURLHTTPUpgraded)
	case !strings.HasPrefix(lower, "https://"):
		trimmed = "https://" + trimmed
	}

	parsed, err := url.Parse(trimmed)
	if err != nil {
		return "", warnings, fmt.Errorf(util.ErrorTextNgtsTokenURLInvalid, err.Error())
	}

	host := strings.ToLower(parsed.Hostname())
	if host == "" || !strings.HasSuffix(host, util.NgtsTrustedTokenHostSuffix) {
		return "", warnings, fmt.Errorf(util.ErrorTextNgtsTokenURLUntrustedHost, host, util.NgtsTrustedTokenHostSuffix)
	}

	return trimmed, warnings, nil
}

func getWarnings(entry *venafiSecretEntry, name string) []string {

	warnings := []string{}

	if entry.TppURL != "" {
		warnings = append(warnings, "tpp_url is deprecated, please use url instead")
	}
	if entry.CloudURL != "" {
		warnings = append(warnings, "cloud_url is deprecated, please use url instead")
	}
	if entry.TppUser != "" {
		warnings = append(warnings, "tpp_user is deprecated, please use access_token token instead")
	}
	if entry.TppPassword != "" {
		warnings = append(warnings, "tpp_password is deprecated, please use access_token instead")
	}
	//Include success message in warnings
	if len(warnings) > 0 {
		warnings = append(warnings, "CyberArk secret "+name+" saved successfully")
	}
	return warnings
}

type venafiSecretEntry struct {
	URL             string        `json:"url"`
	Zone            string        `json:"zone"`
	TppURL          string        `json:"tpp_url"`
	TppUser         string        `json:"tpp_user"`
	TppPassword     string        `json:"tpp_password"`
	AccessToken     string        `json:"access_token"`
	RefreshToken    string        `json:"refresh_token"`
	RefreshToken2   string        `json:"refresh_token_2"`
	RefreshInterval time.Duration `json:"refresh_interval"`
	NextRefresh     time.Time     `json:"next_refresh"`
	CloudURL        string        `json:"cloud_url"`
	Apikey          string        `json:"apikey"`
	TrustBundleFile string        `json:"trust_bundle_file"`
	Fakemode        bool          `json:"fakemode"`
	ClientId        string        `json:"client_id"`

	// NGTS (Strata Cloud Manager) service-account / pre-issued-token fields.
	NgtsTokenURL     string `json:"ngts_token_url"`
	NgtsClientId     string `json:"ngts_client_id"`
	NgtsClientSecret string `json:"ngts_client_secret"`
	NgtsScope        string `json:"ngts_scope"`
	NgtsAccessToken  string `json:"ngts_access_token"`
}

// isNgts reports whether any NGTS field is set, i.e. the secret is meant for the
// Strata Cloud Manager (NGTS) backend. Selection is by field presence, mirroring the
// implicit backend selection used for TPP/Cloud.
func (p *venafiSecretEntry) isNgts() bool {
	return p.NgtsTokenURL != "" || p.NgtsClientId != "" || p.NgtsClientSecret != "" ||
		p.NgtsScope != "" || p.NgtsAccessToken != ""
}

func (p *venafiSecretEntry) ToResponseData() map[string]interface{} {
	responseData := map[string]interface{}{
		//Sensible data will not be disclosed.
		//tpp_password, api_key, access_token, refresh_token

		"url":               p.URL,
		"zone":              p.Zone,
		"tpp_user":          p.TppUser,
		"tpp_password":      p.getStringMask(),
		"access_token":      p.getStringMask(),
		"refresh_token":     p.getStringMask(),
		"refresh_token_2":   p.getStringMask(),
		"refresh_interval":  util.ShortDurationString(p.RefreshInterval),
		"next_refresh":      p.NextRefresh,
		"apikey":            p.getStringMask(),
		"trust_bundle_file": p.TrustBundleFile,
		"fakemode":          p.Fakemode,
		"client_id":         p.ClientId,

		//ngts_client_secret and ngts_access_token are sensitive and stay masked
		"ngts_token_url":     p.NgtsTokenURL,
		"ngts_client_id":     p.NgtsClientId,
		"ngts_client_secret": p.getStringMask(),
		"ngts_scope":         p.NgtsScope,
		"ngts_access_token":  p.getStringMask(),
	}
	return responseData
}

func (p *venafiSecretEntry) getStringMask() string {
	return stringMask
}

const (
	stringMask                    = "********"
	pathListVenafiSecretsHelpSyn  = `List the existing CyberArk Secrets in this backend`                                    // #nosec
	pathListVenafiSecretsHelpDesc = `CyberArk Secrets will be listed by the secret name.`                                   // #nosec
	pathVenafiSecretsHelpSyn      = `Manage the CyberArk Secrets that can be created with this backend.`                    // #nosec
	pathVenafiSecretsHelpDesc     = `This path lets you manage the CyberArk Secrets that can be created with this backend.` // #nosec
)
