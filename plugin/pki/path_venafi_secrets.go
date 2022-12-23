package pki

import (
	"context"
	"fmt"
	"time"

	"github.com/hashicorp/vault/sdk/framework"
	"github.com/hashicorp/vault/sdk/logical"
)

func pathCredentialsList(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: CredentialsRootPath + "?$",
		Fields:  nil,
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ListOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretList,
				Summary:  "List all venafi secrets",
			},
		},
		HelpSynopsis:    pathListVenafiSecretsHelpSyn,
		HelpDescription: pathListVenafiSecretsHelpDesc,
	}
}

func pathCredentials(b *backend) *framework.Path {
	return &framework.Path{
		Pattern: CredentialsRootPath + framework.GenericNameRegex("name"),
		Fields: map[string]*framework.FieldSchema{
			"name": {
				Type:        framework.TypeString,
				Description: "Name of the authentication object",
				Required:    true,
			},
			"zone": {
				Type: framework.TypeString,
				Description: `Name of Venafi Platform policy or Venafi Cloud project zone. 
Example for Platform: testpolicy\\vault
Example for Venafi Cloud: e33f3e40-4e7e-11ea-8da3-b3c196ebeb0b`,
				Required: true,
			},
			"tpp_url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi Platform. Example: https://tpp.venafi.example/vedsdk. Deprecated, use 'url' instead`,
				Deprecated:  true,
			},
			"url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi API Endpoint. Example: https://tpp.venafi.example`,
				Required:    true,
			},

			"cloud_url": {
				Type:        framework.TypeString,
				Description: `URL for Venafi Cloud. Set it only if you want to use non production Cloud. Deprecated, use 'url' instead`,
				Deprecated:  true,
			},
			"tpp_user": {
				Type:        framework.TypeString,
				Description: `WebSDK username for Venafi Platform API`,
				Deprecated:  true,
			},
			"tpp_password": {
				Type:        framework.TypeString,
				Description: `Password for WebSDK user`,
				Deprecated:  true,
			},
			"access_token": {
				Type:        framework.TypeString,
				Description: `Access token for TPP; omit if secrets engine should manage token refreshes`,
			},
			"refresh_token": {
				Type:        framework.TypeString,
				Description: `Primary refresh token for updating TPP access token before it expires`,
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
				Description: `API key for Venafi Cloud. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
			},
			"trust_bundle_file": {
				Type: framework.TypeString,
				Description: `Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.
Example: trust_bundle_file="/path-to/bundle.pem""`,
			},
			"fakemode": {
				Type:        framework.TypeBool,
				Description: `Set it to true to use fake CA instead of Cloud or Platform to issue certificates. Useful for testing.`,
				Default:     false,
			},
			"client_id": {
				Type:        framework.TypeString,
				Description: `Use to specify the application that will be using the token.`,
				Default:     `hashicorp-vault-by-venafi`,
			},
		},
		Operations: map[logical.Operation]framework.OperationHandler{
			logical.ReadOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretRead,
				Summary:  "Read the properties of a venafi secret and displays it to the user.",
			},
			logical.UpdateOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretCreate,
				Summary:  "Create a venafi secret",
			},
			logical.DeleteOperation: &framework.PathOperation{
				Callback: b.pathVenafiSecretDelete,
				Summary:  "Delete a venafi secret",
			},
		},
		HelpSynopsis:    pathVenafiSecretsHelpSyn,
		HelpDescription: pathVenafiSecretsHelpDesc,
	}
}

const (
	CredentialsRootPath         = `venafi/`
	tokenMode                   = `TPP Token (access_token, refresh_token)` // #nosec G101
	tppMode                     = `TPP Credentials (tpp_user, tpp_password)`
	cloudMode                   = `Cloud API Key (apikey)`
	errorMultiModeMessage       = `can't specify both: %s and %s modes in the same venafi secret`
	errorTextURLEmpty           = `"url" argument is required`
	errorTextZoneEmpty          = `"zone" argument is required`
	errorTextInvalidMode        = "invalid mode: fakemode or apikey or tpp credentials or tpp access token required"
	errorTextNeed2RefreshTokens = "secrets engine requires 2 refresh tokens for no impact token refresh"
)

var (
	errorTextMixedTPPAndToken   = fmt.Sprintf(errorMultiModeMessage, tppMode, tokenMode)
	errorTextMixedTPPAndCloud   = fmt.Sprintf(errorMultiModeMessage, tppMode, cloudMode)
	errorTextMixedTokenAndCloud = fmt.Sprintf(errorMultiModeMessage, tokenMode, cloudMode)
)

func (b *backend) pathVenafiSecretList(ctx context.Context, req *logical.Request, d *framework.FieldData) (*logical.Response, error) {
	entries, err := req.Storage.List(ctx, CredentialsRootPath)
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
	err := req.Storage.Delete(ctx, CredentialsRootPath+data.Get("name").(string))
	if err != nil {
		return nil, err
	}
	return nil, nil
}

func (b *backend) pathVenafiSecretCreate(ctx context.Context, req *logical.Request, data *framework.FieldData) (*logical.Response, error) {
	var err error
	name := data.Get("name").(string)

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
		URL:             url,
		Zone:            data.Get("zone").(string),
		TppURL:          tppUrl,
		TppUser:         data.Get("tpp_user").(string),
		TppPassword:     data.Get("tpp_password").(string),
		AccessToken:     data.Get("access_token").(string),
		RefreshToken:    data.Get("refresh_token").(string),
		RefreshToken2:   data.Get("refresh_token_2").(string),
		RefreshInterval: time.Duration(data.Get("refresh_interval").(int)) * time.Second,
		NextRefresh:     time.Now(),
		CloudURL:        cloudUrl,
		Apikey:          data.Get("apikey").(string),
		TrustBundleFile: data.Get("trust_bundle_file").(string),
		Fakemode:        data.Get("fakemode").(bool),
		ClientId:        data.Get("client_id").(string),
	}

	err = validateVenafiSecretEntry(entry)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
	}

	if entry.RefreshToken != "" && !entry.Fakemode {

		for i := 0; i < 2; i++ {

			cfg, err := createConfigFromFieldData(entry)
			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}

			tokenInfo, err := getAccessData(cfg)
			if err != nil {
				return logical.ErrorResponse(err.Error()), nil
			}

			if i == 0 && tokenInfo.Refresh_token != "" {
				// ensure refresh interval is proactive by not allowing it to be longer than access token is valid
				maxInterval := time.Until(time.Unix(int64(tokenInfo.Expires), 0)).Round(time.Minute) - time.Duration(30)*time.Second
				if maxInterval < entry.RefreshInterval {
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
	}

	//Store it
	jsonEntry, err := logical.StorageEntryJSON(CredentialsRootPath+name, entry)
	if err != nil {
		return nil, err
	}

	err = req.Storage.Put(ctx, jsonEntry)
	if err != nil {
		return nil, err
	}

	var logResp *logical.Response

	warnings := getWarnings(entry, name)

	if cap(warnings) > 0 {
		logResp = &logical.Response{

			Data:     map[string]interface{}{},
			Redirect: "",
			Warnings: warnings,
		}
		return logResp, nil
	}

	return nil, nil
}

func (b *backend) getVenafiSecret(ctx context.Context, s logical.Storage, name string) (*venafiSecretEntry, error) {
	entry, err := s.Get(ctx, CredentialsRootPath+name)
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
	if !entry.Fakemode && entry.Apikey == "" && (entry.TppUser == "" || entry.TppPassword == "") && entry.RefreshToken == "" && entry.AccessToken == "" {
		return fmt.Errorf(errorTextInvalidMode)
	}

	//Only validate other fields if mode is not fakemode
	if !entry.Fakemode {
		//When api key is null, that means
		if entry.URL == "" && entry.Apikey == "" {
			return fmt.Errorf(errorTextURLEmpty)
		}

		if entry.Zone == "" {
			return fmt.Errorf(errorTextZoneEmpty)
		}

		if entry.TppUser != "" && entry.Apikey != "" {
			return fmt.Errorf(errorTextMixedTPPAndCloud)
		}

		if entry.TppUser != "" && entry.AccessToken != "" {
			return fmt.Errorf(errorTextMixedTPPAndToken)
		}

		if entry.AccessToken != "" && entry.Apikey != "" {
			return fmt.Errorf(errorTextMixedTokenAndCloud)
		}

		if (entry.RefreshToken != "" && entry.RefreshToken2 == "") || (entry.RefreshToken == "" && entry.RefreshToken2 != "") {
			return fmt.Errorf(errorTextNeed2RefreshTokens)
		}
	}
	return nil
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
		warnings = append(warnings, "Venafi secret "+name+" saved successfully")
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
		"refresh_interval":  shortDurationString(p.RefreshInterval),
		"next_refresh":      p.NextRefresh,
		"apikey":            p.getStringMask(),
		"trust_bundle_file": p.TrustBundleFile,
		"fakemode":          p.Fakemode,
		"client_id":         p.ClientId,
	}
	return responseData
}

func (p *venafiSecretEntry) getStringMask() string {
	return stringMask
}

const (
	stringMask                    = "********"
	pathListVenafiSecretsHelpSyn  = `List the existing Venafi Secrets in this backend`                                    // #nosec
	pathListVenafiSecretsHelpDesc = `Venafi Secrets will be listed by the secret name.`                                   // #nosec
	pathVenafiSecretsHelpSyn      = `Manage the Venafi Secrets that can be created with this backend.`                    // #nosec
	pathVenafiSecretsHelpDesc     = `This path lets you manage the Venafi Secrets that can be created with this backend.` // #nosec
)
