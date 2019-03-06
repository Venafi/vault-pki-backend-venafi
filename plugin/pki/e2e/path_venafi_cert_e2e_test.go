package e2e

import (
	"testing"

	"bufio"
	"fmt"
	. "github.com/onsi/ginkgo"
	"github.com/onsi/ginkgo/reporters"
	. "github.com/onsi/gomega"
	"strings"
	"time"
)

func init() {
	fmt.Println("Initilazing Vault with consul backend")
	commandWithArgs("docker-compose", "down", "--remove-orphans")
	commandWithArgs("docker", "images")
	commandWithArgs("docker-compose", "up", "-d")
	time.Sleep(20)

	init := run(fmt.Sprintf("docker exec %s vault operator init -key-shares=1 -key-threshold=1", vaultContainerName))

	scanner := bufio.NewScanner(strings.NewReader(string(init)))
	var keyLine string
	var tokenLine string
	var s []string

	for scanner.Scan() {
		if strings.Contains(scanner.Text(), "Unseal Key") {
			keyLine = scanner.Text()
		}
		if strings.Contains(scanner.Text(), "Initial Root Token") {
			tokenLine = scanner.Text()
		}
	}

	s = strings.Split(keyLine, " ")
	key := s[3]
	s = strings.Split(tokenLine, " ")
	token := s[3]

	unseal := run(fmt.Sprintf("docker exec %s vault operator unseal %s", vaultContainerName, key))
	fmt.Println(unseal)

	auth := run(fmt.Sprintf("docker exec %s vault login %s", vaultContainerName, token))
	fmt.Println(auth)

	s = strings.Split(run(fmt.Sprintf("docker exec %s sha256sum /vault_plugin/venafi-pki-backend", vaultContainerName)), " ")
	sha256 := s[0]
	fmt.Println("sha256 is:", sha256)

	write_pki := run(fmt.Sprintf("docker exec %s vault write sys/plugins/catalog/venafi-pki-backend sha_256=%s command=venafi-pki-backend", vaultContainerName, sha256))
	fmt.Println(write_pki)
	enable_pki := run(fmt.Sprintf("docker exec %s vault secrets enable -path=venafi-pki -plugin-name=venafi-pki-backend plugin", vaultContainerName))
	fmt.Println(enable_pki)
}

func TestPki(t *testing.T) {
	RegisterFailHandler(Fail)
	junitReporter := reporters.NewJUnitReporter("junit_00.xml")
	RunSpecsWithDefaultAndCustomReporters(t, "Integration tests for Venafi Vault PKI backend", []Reporter{junitReporter})
}
