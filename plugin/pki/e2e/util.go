package e2e

import (
	"fmt"
	"github.com/Venafi/vault-pki-backend-venafi/plugin/pki"
	"github.com/onsi/ginkgo"
	"github.com/rendon/testcli"
	"strings"
)

func testRunCmd(some ...string) (out, err string, exitCode int) {
	cmd := splitAndFlat(some)
	testcli.Run(cmd[0], cmd[1:]...)
	if testcli.Failure() {
		exitCode = 1
	}
	return testcli.Stdout(), testcli.Stderr(), exitCode
}

type vaultJSONCertificate struct {
	Data pki.VenafiCert
}

func splitAndFlat(parts ...interface{}) (ret []string) {
	for _, part := range parts {
		switch part := part.(type) {
		case string:
			ret = append(ret, strings.Fields(part)...)
		case []string:
			for _, s := range part {
				ret = append(ret, strings.Fields(s)...)
			}
		default:
			fmt.Printf("DEFAULT: %T\n", part)
		}
	}
	return
}

func testRun(cmd string) (out, err string, exitCode int) {
	out, err, exitCode = testRunCmd(cmd)
	fmt.Fprintf(ginkgo.GinkgoWriter,
		"===CMD: %s\n===OUT:%s\n===ERR:%s\n===EXIT(%d)",
		strings.Fields(cmd), out, err, exitCode)
	return
}
