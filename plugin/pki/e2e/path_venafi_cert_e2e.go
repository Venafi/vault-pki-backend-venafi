package e2e

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"strings"

	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki"
	"github.com/Venafi/vault-pki-backend-venafi/plugin/util"
	"github.com/Venafi/vcert/v5/test"
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"
)

const (
	vaultContainerName = "vault-pki-backend-venafi_vault_1"
)

var _ = Describe("Vault PKI Venafi backend e2e tests	", func() {
	var (
		cmd  string
		out  string
		err  string
		code int
	)

	type endpointConnectionId int

	const (
		tpp endpointConnectionId = iota
		cloud
		fake
		tppToken
		roleOpts = "venafi_secret=%s %s"
	)

	type endpointConnection struct {
		id        endpointConnectionId
		name      string
		roleOpt   string
		enabled   bool
		issuerCN  string
		venafiOpt string
	}

	ctx := pki.GetContext()

	defaultOpts := "generate_lease=true store_by_cn=true store_pkey=true store_by_serial=true"

	var endpoints = []endpointConnection{
		{fake,
			"fake",
			fmt.Sprintf(roleOpts, "fakeVenafi", defaultOpts),
			ctx.FakeTestingEnabled,
			ctx.FakeIssuerCN,
			"fakemode=true",
		},
		{tpp,
			"tpp",
			fmt.Sprintf(roleOpts, "tppVenafi", defaultOpts),
			ctx.TPPTestingEnabled,
			ctx.TPPIssuerCN,
			fmt.Sprintf("tpp_url=%s tpp_user=%s tpp_password=%s zone=%s trust_bundle_file=/opt/venafi/bundle.pem", ctx.TPPurl, ctx.TPPuser, ctx.TPPPassword, ctx.TPPZone),
		},
		{cloud,
			"cloud",
			fmt.Sprintf(roleOpts, "cloudVenafi", defaultOpts),
			ctx.CloudTestingEnabled,
			ctx.CloudIssuerCN,
			fmt.Sprintf("cloud_url=%s zone=%s apikey=%s", ctx.CloudUrl, ctx.CloudZone, ctx.CloudAPIkey),
		},
		{tppToken,
			"tpp_token",
			fmt.Sprintf(roleOpts, "tokenVenafi", defaultOpts),
			ctx.TPPTestingEnabled,
			ctx.TPPIssuerCN,
			fmt.Sprintf("url=%s access_token=%s zone=%s trust_bundle_file=/opt/venafi/bundle.pem", ctx.TokenUrl, ctx.AccessToken, ctx.TPPZone),
		},
	}

	Describe("Checking vault status	", func() {

		Describe("Vault status", func() {
			It("should return that Vault is unseald", func() {
				cmd = fmt.Sprintf("docker exec %s vault status", vaultContainerName)
				By("running " + cmd)
				out, err, code := testRun(cmd)
				Expect(code).To(BeZero())
				Expect(out).To(ContainSubstring("Sealed          false"))
				Expect(err).To(BeEmpty())
			})
		})
	})

	Describe("Enrolling certificates for test endpoints", func() {
		Describe("with defaults", func() {
			for _, endpoint := range endpoints {
				if !endpoint.enabled {
					continue
				}
				Context("with "+endpoint.name, func() {
					It("Writing venafi secret configuration", func() {
						cmd = fmt.Sprintf(`docker exec %s vault write venafi-pki/venafi/%s `+endpoint.venafiOpt, vaultContainerName, endpoint.name+"Venafi")
						By("Running " + cmd)
						out, err, code = testRun(cmd)
						Expect(code).To(BeZero())
						Expect(out).To(MatchRegexp("Success! Data written to: venafi-pki/venafi/" + endpoint.name + "Venafi"))
					})
					It("Writing role configuration", func() {
						cmd = fmt.Sprintf(
							`docker exec %s vault write venafi-pki/roles/%s
							`+endpoint.roleOpt,
							vaultContainerName, endpoint.name)
						By("Running " + cmd)
						out, err, code = testRun(cmd)
						Expect(code).To(BeZero())
						Expect(out).To(MatchRegexp("Success! Data written to: venafi-pki/roles/" + endpoint.name))
					})
					cn := test.RandCN()
					It("Enrolling certificate for "+endpoint.name, func() {
						dns1 := "alt-" + test.RandCN()
						dns2 := "alt-" + test.RandCN()
						cmd = fmt.Sprintf(
							`docker exec %s vault write venafi-pki/issue/%s common_name=%s alt_names=%s,%s -format=json`,
							vaultContainerName, endpoint.name, cn, dns1, dns2)

						By("Should run " + cmd)
						out, err, code = testRun(cmd)
						Expect(code).To(BeZero())
						Expect(out).To(ContainSubstring("----BEGIN CERTIFICATE-----"))
						Expect(err).To(BeEmpty())

						By("Should return valid JSON")
						cert := vaultJSONCertificate{}
						response := json.Unmarshal([]byte(out), &cert)
						Expect(response).To(BeZero())

						By("Should be valid certificate")
						certificate := strings.Join([]string{cert.Data.Certificate}, "\n")
						pemBlock, _ := pem.Decode([]byte(certificate))
						parsedCertificate, parseErr := x509.ParseCertificate(pemBlock.Bytes)
						Expect(parseErr).To(BeZero())

						haveCN := parsedCertificate.Subject.CommonName
						By("Should have requested CN " + cn + " equal to " + haveCN)
						Expect(haveCN).To(Equal(cn))

						//Skip DNS check for cloud since int not implemented in Condor.
						if endpoint.id == tpp {
							wantDNSNames := []string{cn, dns1, dns2}
							haveDNSNames := parsedCertificate.DNSNames
							By("Should have requested SANs and CN in DNSNames " + strings.Join(wantDNSNames, " ") + " same as " + strings.Join(haveDNSNames, " "))
							Expect(util.SameStringSlice(haveDNSNames, wantDNSNames)).To(BeTrue())
						}

						By("Should have valid issuer CN")
						haveIssuerCN := parsedCertificate.Issuer.CommonName
						Expect(haveIssuerCN).To(Equal(endpoint.issuerCN))

					})
					It("Fetching "+endpoint.name+" endpoint certificate with CN "+cn, func() {
						By("Should be listed in certificates list")
						cmd = fmt.Sprintf(`docker exec %s vault list venafi-pki/certs`, vaultContainerName)
						out, err, code = testRun(cmd)
						Expect(code).To(BeZero())
						Expect(out).To(MatchRegexp(cn))

						By("Should return valid JSON")
						cmd = fmt.Sprintf(`docker exec %s vault read -format=json venafi-pki/cert/%s`, vaultContainerName, cn)
						fmt.Println(cmd)
						out, err, code = testRun(cmd)
						cert := vaultJSONCertificate{}
						response := json.Unmarshal([]byte(out), &cert)
						Expect(response).To(BeZero())

						By("Should be valid certificate")
						certificate := strings.Join([]string{cert.Data.Certificate}, "\n")
						pemBlock, _ := pem.Decode([]byte(certificate))
						parsedCertificate, parseErr := x509.ParseCertificate(pemBlock.Bytes)
						Expect(parseErr).To(BeZero())

						By("Should have requested CN")
						haveCN := parsedCertificate.Subject.CommonName
						Expect(haveCN).To(Equal(cn))
					})

				})
			}
		})
	})

})
