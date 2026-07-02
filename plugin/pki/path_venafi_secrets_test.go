package pki

import (
	"context"
	"testing"

	"github.com/Venafi/vcert/v5/pkg/endpoint"
	"github.com/hashicorp/vault/sdk/logical"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
)

func TestVenafiSecretValidate(t *testing.T) {
	entry := &venafiSecretEntry{}

	err := validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextInvalidMode {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextInvalidMode, err)
	}

	entry = &venafiSecretEntry{
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextURLEmpty {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextURLEmpty, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://ha-tpp12.sqlha.com:5008/vedsdk",
		AccessToken: "foo123bar==",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextZoneEmpty {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextZoneEmpty, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Zone:        "devops\\vcert",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		TppUser:     "admin",
		TppPassword: "xxxx",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextMixedTPPAndCloud {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextMixedTPPAndCloud, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Zone:        "devops\\vcert",
		AccessToken: "foo123bar==",
		TppUser:     "admin",
		TppPassword: "xxxx",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextMixedTPPAndToken {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextMixedTPPAndToken, err)
	}

	entry = &venafiSecretEntry{
		URL:         "https://qa-tpp.exmple.com/vedsdk",
		Zone:        "devops\\vcert",
		AccessToken: "foo123bar==",
		Apikey:      "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}

	err = validateVenafiSecretEntry(entry)
	if err == nil {
		t.Fatalf("Expecting error")
	}
	if err.Error() != util.ErrorTextMixedTokenAndCloud {
		t.Fatalf("Expecting error %s but got %s", util.ErrorTextMixedTokenAndCloud, err)
	}
}

func TestNgtsSecretValidate(t *testing.T) {
	const (
		validTokenURL = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"
		validScope    = "tsg_id:1234567890"
	)

	// Valid service-account secret (url omitted on purpose — allowed for NGTS at v5.13.7).
	entry := &venafiSecretEntry{
		Zone:             "my-cit",
		NgtsClientId:     "svc@1234567890.iam.panserviceaccount.com",
		NgtsClientSecret: "secret",
		NgtsTokenURL:     validTokenURL,
		NgtsScope:        validScope,
	}
	if err := validateVenafiSecretEntry(entry); err != nil {
		t.Fatalf("expected valid NGTS service-account secret, got: %s", err)
	}

	// Valid pre-issued access-token secret (no token_url/scope required).
	entry = &venafiSecretEntry{Zone: "my-cit", NgtsAccessToken: "bearer-xyz"}
	if err := validateVenafiSecretEntry(entry); err != nil {
		t.Fatalf("expected valid NGTS access-token secret, got: %s", err)
	}

	cases := []struct {
		name     string
		entry    *venafiSecretEntry
		expected string
	}{
		{
			name:     "missing zone",
			entry:    &venafiSecretEntry{NgtsAccessToken: "bearer-xyz"},
			expected: util.ErrorTextZoneEmpty,
		},
		{
			name:     "incomplete creds (no client_secret)",
			entry:    &venafiSecretEntry{Zone: "my-cit", NgtsClientId: "svc", NgtsTokenURL: validTokenURL, NgtsScope: validScope},
			expected: util.ErrorTextNgtsCredsIncomplete,
		},
		{
			name:     "missing token_url in service-account mode",
			entry:    &venafiSecretEntry{Zone: "my-cit", NgtsClientId: "svc", NgtsClientSecret: "secret", NgtsScope: validScope},
			expected: util.ErrorTextNgtsTokenURLEmpty,
		},
		{
			name:     "invalid scope",
			entry:    &venafiSecretEntry{Zone: "my-cit", NgtsClientId: "svc", NgtsClientSecret: "secret", NgtsTokenURL: validTokenURL, NgtsScope: "tsg_id:123"},
			expected: util.ErrorTextNgtsScopeInvalid,
		},
		{
			name:     "mixed with cloud apikey",
			entry:    &venafiSecretEntry{Zone: "my-cit", NgtsAccessToken: "bearer-xyz", Apikey: "k"},
			expected: util.ErrorTextMixedNgtsAndCloud,
		},
		{
			name:     "mixed with TPP token",
			entry:    &venafiSecretEntry{Zone: "my-cit", NgtsAccessToken: "bearer-xyz", AccessToken: "tok"},
			expected: util.ErrorTextMixedNgtsAndToken,
		},
		{
			name:     "mixed with TPP user/password",
			entry:    &venafiSecretEntry{Zone: "my-cit", NgtsAccessToken: "bearer-xyz", TppUser: "u", TppPassword: "p"},
			expected: util.ErrorTextMixedNgtsAndTPP,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateVenafiSecretEntry(tc.entry)
			if err == nil {
				t.Fatalf("expected error %q, got nil", tc.expected)
			}
			if err.Error() != tc.expected {
				t.Fatalf("expected error %q, got %q", tc.expected, err.Error())
			}
		})
	}
}

func TestNormalizeNgtsTokenURL(t *testing.T) {
	const trustedHTTPS = "https://auth.apps.paloaltonetworks.com/oauth2/access_token"

	// http:// is upgraded to https:// with a warning.
	got, warns, err := normalizeNgtsTokenURL("http://auth.apps.paloaltonetworks.com/oauth2/access_token")
	if err != nil {
		t.Fatal(err)
	}
	if got != trustedHTTPS {
		t.Fatalf("expected %q, got %q", trustedHTTPS, got)
	}
	if len(warns) != 1 || warns[0] != util.WarningNgtsTokenURLHTTPUpgraded {
		t.Fatalf("expected http-upgrade warning, got %v", warns)
	}

	// A scheme-less value defaults to https:// with no warning.
	got, warns, err = normalizeNgtsTokenURL("auth.apps.paloaltonetworks.com/oauth2/access_token")
	if err != nil {
		t.Fatal(err)
	}
	if got != trustedHTTPS {
		t.Fatalf("expected %q, got %q", trustedHTTPS, got)
	}
	if len(warns) != 0 {
		t.Fatalf("expected no warning, got %v", warns)
	}

	// A trusted https:// host passes through unchanged.
	got, _, err = normalizeNgtsTokenURL(trustedHTTPS)
	if err != nil {
		t.Fatal(err)
	}
	if got != trustedHTTPS {
		t.Fatalf("expected %q, got %q", trustedHTTPS, got)
	}

	// Untrusted hosts are rejected (fail-closed), even when reached via http://.
	if _, _, err = normalizeNgtsTokenURL("https://evil.example.com/oauth2/access_token"); err == nil {
		t.Fatal("expected untrusted-host rejection for https evil host")
	}
	if _, _, err = normalizeNgtsTokenURL("http://evil.example.com/token"); err == nil {
		t.Fatal("expected untrusted-host rejection for http evil host")
	}

	// Look-alike domain must not be accepted by the suffix check.
	if _, _, err = normalizeNgtsTokenURL("https://auth.evilpaloaltonetworks.com/token"); err == nil {
		t.Fatal("expected rejection of look-alike domain")
	}

	// Empty input is passed through (emptiness is enforced by validation).
	got, warns, err = normalizeNgtsTokenURL("")
	if err != nil || got != "" || warns != nil {
		t.Fatalf("expected empty passthrough, got %q %v %v", got, warns, err)
	}
}

func TestGetConfigNGTSServiceAccount(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		t.Fatal(err)
	}

	secret := &venafiSecretEntry{
		URL:              "https://api.strata.paloaltonetworks.com/ngts",
		Zone:             "my-cit",
		NgtsClientId:     "svc@1234567890.iam.panserviceaccount.com",
		NgtsClientSecret: "secret",
		NgtsTokenURL:     "https://auth.apps.paloaltonetworks.com/oauth2/access_token",
		NgtsScope:        "tsg_id:1234567890",
	}
	entry, err := logical.StorageEntryJSON(util.CredentialsRootPath+"ngts", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	role := &roleEntry{VenafiSecret: "ngts"}
	cfg, err := b.getConfig(ctx, &logical.Request{Storage: storage}, role, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnectorType != endpoint.ConnectorTypeNGTS {
		t.Fatalf("expected NGTS connector type, got %v", cfg.ConnectorType)
	}
	if cfg.BaseUrl != secret.URL {
		t.Fatalf("expected BaseUrl %q, got %q", secret.URL, cfg.BaseUrl)
	}
	if cfg.Credentials == nil {
		t.Fatal("expected credentials to be set")
	}
	if cfg.Credentials.ClientId != secret.NgtsClientId ||
		cfg.Credentials.ClientSecret != secret.NgtsClientSecret ||
		cfg.Credentials.TokenURL != secret.NgtsTokenURL ||
		cfg.Credentials.Scope != secret.NgtsScope {
		t.Fatalf("NGTS service-account credentials not forwarded correctly: %#v", cfg.Credentials)
	}
	if cfg.Credentials.AccessToken != "" {
		t.Fatalf("did not expect an access token in service-account mode, got %q", cfg.Credentials.AccessToken)
	}
}

func TestGetConfigNGTSAccessToken(t *testing.T) {
	ctx := context.Background()
	storage := &logical.InmemStorage{}
	conf := logical.TestBackendConfig()
	conf.StorageView = storage
	b := Backend(conf)
	if err := b.Setup(ctx, conf); err != nil {
		t.Fatal(err)
	}

	secret := &venafiSecretEntry{
		Zone:            "my-cit",
		NgtsAccessToken: "bearer-xyz",
	}
	entry, err := logical.StorageEntryJSON(util.CredentialsRootPath+"ngts-token", secret)
	if err != nil {
		t.Fatal(err)
	}
	if err := storage.Put(ctx, entry); err != nil {
		t.Fatal(err)
	}

	role := &roleEntry{VenafiSecret: "ngts-token"}
	cfg, err := b.getConfig(ctx, &logical.Request{Storage: storage}, role, false)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ConnectorType != endpoint.ConnectorTypeNGTS {
		t.Fatalf("expected NGTS connector type, got %v", cfg.ConnectorType)
	}
	if cfg.Credentials == nil || cfg.Credentials.AccessToken != secret.NgtsAccessToken {
		t.Fatalf("expected access token %q to be forwarded, got %#v", secret.NgtsAccessToken, cfg.Credentials)
	}
	if cfg.Credentials.ClientId != "" || cfg.Credentials.ClientSecret != "" {
		t.Fatalf("did not expect service-account fields in access-token mode: %#v", cfg.Credentials)
	}
}
