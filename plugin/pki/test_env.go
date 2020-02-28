package pki

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"github.com/hashicorp/go-hclog"
	"github.com/hashicorp/vault/api"
	vaulthttp "github.com/hashicorp/vault/http"
	"github.com/hashicorp/vault/logical"
	"github.com/hashicorp/vault/vault"
	"log"
	"net"
	"os"
	"testing"
	"time"
)

type testEnv struct {

	Backend logical.Backend
	Context context.Context
	Storage logical.Storage

	TestData testData
}

type testData struct {
	cert        string
	private_key string
	wrong_cert  string
	wrong_pkey  string
	cn          string
	dns_ns      string
	dns_ip      string
	only_ip     string
	dns_email   string
	provider    string
	signCSR     bool
	csrPK       []byte
}


func(e *testEnv) Fake_BaseEnroll(t *testing.T) {
	data := testData{}
	rand := randSeq(9)
	domain := "venafi.example.com"
	data.cn = rand + "." + domain
	data.dns_ns = "alt-" + data.cn
	data.dns_ip = "192.168.1.1"
	data.only_ip = "127.0.0.1"
	data.dns_email = "venafi@example.com"

	coreConfig := &vault.CoreConfig{
		LogicalBackends: map[string]logical.Factory{
			"pki": Factory,
		},
		Logger: hclog.NewNullLogger(),
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
		t.Fatalf("Error configuring role: %s", err)
	}

	resp, err := client.Logical().Write("pki/issue/example", map[string]interface{}{
		"common_name": data.cn,
		"alt_names":   fmt.Sprintf("%s,%s,%s", data.dns_ns, data.dns_ip, data.dns_email),
		"ip_sans":     []string{data.only_ip},
	})
	if err != nil {
		t.Fatalf("Error issuing certificate: %s", err)
	}

	if resp.Data["certificate"] == "" {
		t.Fatalf("Expected a cert to be generated")
	}

	data.cert = resp.Data["certificate"].(string)
	data.private_key = resp.Data["private_key"].(string)

	checkStandartCert(t, data)
}



func checkStandartCert(t *testing.T, data testData) {
	var err error
	log.Println("Testing certificate:", data.cert)
	certPEMBlock, _ := pem.Decode([]byte(data.cert))
	if certPEMBlock == nil {
		t.Fatalf("Certificate data is nil in the pem block")
	}

	if !data.signCSR {
		log.Println("Testing private key:", data.private_key)
		keyPEMBlock, _ := pem.Decode([]byte(data.private_key))
		if keyPEMBlock == nil {
			t.Fatalf("Private key data is nil in thew private key")
		}
		_, err = tls.X509KeyPair([]byte(data.cert), []byte(data.private_key))
		if err != nil {
			t.Fatalf("Error parsing certificate key pair: %s", err)
		}
	} else {
		_, err = tls.X509KeyPair([]byte(data.cert), []byte(data.csrPK))
		if err != nil {
			t.Fatalf("Error parsing certificate key pair: %s", err)
		}
	}

	parsedCertificate, err := x509.ParseCertificate(certPEMBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	if parsedCertificate.Subject.CommonName != data.cn {
		t.Fatalf("Certificate common name expected to be %s but actualy it is %s", parsedCertificate.Subject.CommonName, data.cn)
	}

	//TODO: cloud now have SAN support too. Have to implement it
	if data.provider == "tpp" {
		wantDNSNames := []string{data.cn, data.dns_ns, data.dns_ip}
		haveDNSNames := parsedCertificate.DNSNames
		ips := make([]net.IP, 0, 2)
		if data.dns_ip != "" {
			ips = append(ips, net.ParseIP(data.dns_ip))
		}
		if data.only_ip != "" {
			ips = append(ips, net.ParseIP(data.only_ip))
		}
		if !SameStringSlice(haveDNSNames, wantDNSNames) {
			t.Fatalf("Certificate Subject Alternative Names %s doesn't match to requested %s", haveDNSNames, wantDNSNames)
		}

		if !SameIpSlice(ips, parsedCertificate.IPAddresses) {
			t.Fatalf("Certificate IPs %v doesn`t match requested %v", parsedCertificate.IPAddresses, ips)
		}
		//TODO: check email too
		//wantEmail := []string{data.dns_email}
		//TODO: in policies branch Cloud endpoint should start to populate O,C,L.. fields too
		wantOrg := os.Getenv("CERT_O")
		if wantOrg != "" {
			var haveOrg string
			if len(parsedCertificate.Subject.Organization) > 0 {
				haveOrg = parsedCertificate.Subject.Organization[0]
			} else {
				t.Fatalf("Organization in certificate is empty.")
			}
			log.Println("want and have", wantOrg, haveOrg)
			if wantOrg != haveOrg {
				t.Fatalf("Certificate Organization %s doesn't match to requested %s", haveOrg, wantOrg)
			}
		}
	}
}

func newIntegrationTestEnv(t *testing.T) (*testEnv, error) {
	ctx := context.Background()
	defaultLeaseTTLVal := time.Hour * 24
	maxLeaseTTLVal := time.Hour * 24 * 32

	b, err := Factory(context.Background(), &logical.BackendConfig{
		Logger: nil,
		System: &logical.StaticSystemView{
			DefaultLeaseTTLVal: defaultLeaseTTLVal,
			MaxLeaseTTLVal:     maxLeaseTTLVal,
		},
	})
	if err != nil {
		return nil, err
	}
	return &testEnv{
		Backend:   b,
		Context:   ctx,
		Storage:   &logical.InmemStorage{},
	}, nil
}
