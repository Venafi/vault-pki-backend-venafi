package pki

import (
	"context"
	"fmt"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/logical/framework"
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
		HelpSynopsis:    "",
		HelpDescription: "",
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
			"tpp_url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi Platform. Example: https://tpp.venafi.example/vedsdk`,
				Deprecated:  true,
			},
			"url": {
				Type:        framework.TypeString,
				Description: `URL of Venafi Platform. Example: https://tpp.venafi.example/vedsdk, is replacing tpp_url`,
				Required:    true,
			},

			"cloud_url": {
				Type:        framework.TypeString,
				Description: `URL for Venafi Cloud. Set it only if you want to use non production Cloud`,
			},
			"tpp_user": {
				Type:        framework.TypeString,
				Description: `web API user for Venafi Platform Example: admin`,
				Deprecated:  true,
			},
			"tpp_password": {
				Type:        framework.TypeString,
				Description: `Password for web API user Example: password`,
				Deprecated:  true,
			},
			"access_token": {
				Type:        framework.TypeString,
				Description: `Access token for TPP, user should use this for authentication`,
			},
			"refresh_token": {
				Type:        framework.TypeString,
				Description: `Refresh token for updating access TPP token`,
			},
			"trust_bundle_file": {
				Type: framework.TypeString,
				Description: `Use to specify a PEM formatted file with certificates to be used as trust anchors when communicating with the remote server.
								Example:
  									trust_bundle_file = "/full/path/to/bundle.pem""`,
			},
			"apikey": {
				Type:        framework.TypeString,
				Description: `API key for Venafi Cloud. Example: 142231b7-cvb0-412e-886b-6aeght0bc93d`,
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
		HelpSynopsis:    "",
		HelpDescription: "",
	}
}

const (
	CredentialsRootPath   = `venafi/`
	tokenMode             = `TPP Token (access_token, refresh_token)`
	tppMode               = `TPP Credentials (tpp_user, tpp_password)`
	cloudMode             = `Cloud API Key (apikey)`
	errorMultiModeMessage = `can't specify both: %s and %s modes in the same venafi secret`
	errorTextURLEmpty     = `url argument required`
	errorTextInvalidMode  = "invalid mode. fakemode or apikey or tpp credentials or tpp access token required"
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

	cred, err := b.getCredentials(ctx, req.Storage, policyName)
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
	if url == "" {
		url = data.Get("tpp_url").(string)
	}
	if url == "" {
		url = data.Get("cloud_url").(string)
	}

	entry := &credentialsEntry{
		TppUser:         data.Get("tpp_user").(string),
		TppPassword:     data.Get("tpp_password").(string),
		URL:             url,
		AccessToken:     data.Get("access_token").(string),
		RefreshToken:    data.Get("refresh_token").(string),
		Apikey:          data.Get("apikey").(string),
		TrustBundleFile: data.Get("trust_bundle_file").(string),
	}

	err = validateCredentialsEntry(entry)
	if err != nil {
		return logical.ErrorResponse(err.Error()), nil
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

	//respData := map[string]interface{}{}

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

func (b *backend) getCredentials(ctx context.Context, s logical.Storage, name string) (*credentialsEntry, error) {
	entry, err := s.Get(ctx, CredentialsRootPath+name)
	if err != nil {
		return nil, err
	}
	if entry == nil {
		return nil, nil
	}

	var result credentialsEntry
	err = entry.DecodeJSON(&result)
	if err != nil {
		return nil, err
	}

	return &result, nil
}

func validateCredentialsEntry(entry *credentialsEntry) error {
	if entry.Apikey == "" && (entry.TppUser == "" || entry.TppPassword == "") && entry.AccessToken == "" {
		return fmt.Errorf(errorTextInvalidMode)
	}

	if entry.URL == "" {
		return fmt.Errorf(errorTextURLEmpty)
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

	return nil
}

func getWarnings(entry *credentialsEntry, name string) []string {

	warnings := []string{}

	if entry.TppUser != "" {
		warnings = append(warnings, "Role: "+name+", saved successfully, but tpp_user is deprecated, please use access_token token instead")
	}
	if entry.TppPassword != "" {
		warnings = append(warnings, "Role: "+name+", saved successfully, but tpp_password is deprecated, please use access_token instead")
	}

	return warnings
}

type credentialsEntry struct {
	TppUser         string `json:"tpp_user"`
	TppPassword     string `json:"tpp_password"`
	URL             string `json:"url"`
	AccessToken     string `json:"access_token"`
	RefreshToken    string `json:"refresh_token"`
	Apikey          string `json:"apikey"`
	TrustBundleFile string `json:"trust_bundle_file"`
}

func (p *credentialsEntry) ToResponseData() map[string]interface{} {
	var tppPass, accessToken, refreshToken, apiKey string
	if p.TppPassword != "" {
		tppPass = "********"
	}
	if p.AccessToken != "" {
		accessToken = "********"
	}
	if p.RefreshToken != "" {
		refreshToken = "********"
	}
	if p.Apikey != "" {
		apiKey = "********"
	}

	responseData := map[string]interface{}{
		//Sensible data will not be returned.
		//tpp_password, api_key, access_token, refresh_token

		"url":               p.URL,
		"tpp_user":          p.TppUser,
		"tpp_password":      tppPass,
		"access_token":      accessToken,
		"refresh_token":     refreshToken,
		"api_key":           apiKey,
		"trust_bundle_file": p.TrustBundleFile,
	}
	return responseData
}
