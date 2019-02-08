package e2e

import (
	"fmt"
	"github.com/rendon/testcli"
	"os"
	"os/exec"
	"strings"
	. "github.com/onsi/ginkgo"
	. "github.com/Venafi/vault-pki-backend-venafi/plugin/pki"
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
	Data VenafiCert
}

func splitAndFlat(parts ...interface{}) (ret []string) {
	for _, part := range parts {
		switch part.(type) {
		case string:
			ret = append(ret, strings.Fields(part.(string))...)
		case []string:
			for _, s := range part.([]string) {
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
	fmt.Fprintf(GinkgoWriter,
		"===CMD: %s\n===OUT:%s\n===ERR:%s\n===EXIT(%d)",
		strings.Fields(cmd), out, err, exitCode)
	return
}

func run(command string) string {
	var err error
	cmd := splitAndFlat(command)
	fmt.Println("Running: ", cmd)
	out, err := exec.Command(cmd[0], cmd[1:]...).CombinedOutput()
	if err != nil {
		fmt.Println(string(out))
		panic(err)
	}
	return string(out)
}

func commandWithArgs(run string, extraArgs ...string) {
	args := []string{}
	args = append(args, extraArgs...)
	cmd := exec.Command(run, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	err := cmd.Run()
	if err != nil {
		panic(err)
		return
	}
}
