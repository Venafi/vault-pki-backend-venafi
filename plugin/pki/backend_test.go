package pki

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"log"
	"os"
	"testing"
)

var (
	stepCount               = 0
	serialUnderTest         string
	parsedKeyUsageUnderTest int
)

func TestPKI_Fake_BaseEnroll(t *testing.T) {
	rand := randSeq(9)
	domain := "venafi.example.com"
	randCN := rand + "." + domain
	dns_ns := "alt-" + randCN
	dns_ip := "192.168.1.1"
	dns_email := "venafi@example.com"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"fakemode":       true,
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": randCN,
		"alt_names":   fmt.Sprintf("%s,%s,%s", dns_ns, dns_ip, dns_email),
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	cert := resp.Data["certificate"].(string)
	log.Println("Testing certificate:", cert)
	pemBlock, _ := pem.Decode([]byte(cert))
	parsedCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsedCertificate.Subject.CommonName != randCN {
		t.Fatalf("Certificate common name expected to be %s but actualy it is %s", parsedCertificate.Subject.CommonName, randCN)
	}
	wantDNSNames := []string{randCN, dns_ns, dns_ip, dns_email}
	haveDNSNames := parsedCertificate.DNSNames

	if !sameStringSlice(haveDNSNames, wantDNSNames) {
		t.Fatalf("Certificate Subject Alternative Names %s doesn't match to requested %s", haveDNSNames, wantDNSNames)
	}
}

func TestPKI_TPP_BaseEnroll(t *testing.T) {
	rand := randSeq(9)
	domain := "venafi.example.com"
	randCN := rand + "." + domain
	dns_ns := "alt-" + randCN
	dns_ip := "192.168.1.1"
	dns_email := "venafi@example.com"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease":    true,
		"tpp_url":           os.Getenv("TPPURL"),
		"tpp_user":          os.Getenv("TPPUSER"),
		"tpp_password":      os.Getenv("TPPPASSWORD"),
		"zone":              os.Getenv("TPPZONE"),
		"trust_bundle_file": os.Getenv("TRUST_BUNDLE"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": randCN,
		"alt_names":   fmt.Sprintf("%s,%s,%s", dns_ns, dns_ip, dns_email),
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	cert := resp.Data["certificate"].(string)
	log.Println("Testing certificate:", cert)
	pemBlock, _ := pem.Decode([]byte(cert))
	parsedCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsedCertificate.Subject.CommonName != randCN {
		t.Fatalf("Certificate common name expected to be %s but actualy it is %s", parsedCertificate.Subject.CommonName, randCN)
	}
	wantDNSNames := []string{randCN, dns_ns, dns_ip, dns_email}
	haveDNSNames := parsedCertificate.DNSNames

	if !sameStringSlice(haveDNSNames, wantDNSNames) {
		t.Fatalf("Certificate Subject Alternative Names %s doesn't match to requested %s", haveDNSNames, wantDNSNames)
	}
}

func TestPKI_Cloud_BaseEnroll(t *testing.T) {
	rand := randSeq(9)
	domain := "venafi.example.com"
	randCN := rand + "." + domain
	//dns_ns := "alt-" + randCN
	//dns_ip := "192.168.1.1"
	//dns_email := "venafi@example.com"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
	}
	cluster := vault.NewTestCluster(t, coreConfig, &vault.TestClusterOptions{
		HandlerFunc: vaulthttp.Handler,
	})
	cluster.Start()
	defer cluster.Cleanup()

	client := cluster.Cores[0].Client
	var err error
	err = client.Sys().Mount("pki", &api.MountInput{
		Type: "pki",
		Config: api.MountConfigInput{
			DefaultLeaseTTL: "16h",
			MaxLeaseTTL:     "32h",
		},
	})
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.Logical().Write("pki/roles/example", map[string]interface{}{
		"generate_lease": true,
		"cloud_url":      os.Getenv("CLOUDURL"),
		"zone":           os.Getenv("CLOUDZONE"),
		"apikey":         os.Getenv("CLOUDAPIKEY"),
	})
	if err != nil {
		t.Fatal(err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": randCN,
		//"alt_names":   fmt.Sprintf("%s,%s,%s", dns_ns, dns_ip, dns_email),
	})
	if err != nil {
		t.Fatal(err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("expected a cert to be generated")
	}

	cert := resp.Data["certificate"].(string)
	log.Println("Testing certificate:", cert)
	pemBlock, _ := pem.Decode([]byte(cert))
	parsedCertificate, err := x509.ParseCertificate(pemBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if parsedCertificate.Subject.CommonName != randCN {
		t.Fatalf("Certificate common name expected to be %s but actualy it is %s", parsedCertificate.Subject.CommonName, randCN)
	}

	//Cloud doesn't support alt names still
	//wantDNSNames := []string{randCN, dns_ns, dns_ip, dns_email}
	//haveDNSNames := parsedCertificate.DNSNames
	//
	//if !sameStringSlice(haveDNSNames, wantDNSNames) {
	//	t.Fatalf("Certificate Subject Alternative Names %s doesn't match to requested %s", haveDNSNames, wantDNSNames)
	//}
}
