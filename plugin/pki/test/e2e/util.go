package e2e

import (
	"fmt"
	"github.com/Venafi/vault-pki-vcert/plugin/pki"
	. "github.com/onsi/ginkgo"
	"github.com/rendon/testcli"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

type vaultJSONCertificate struct {
	Data pki.VenafiCert
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

func testRunCmd(some ...string) (out, err string, exitCode int) {
	cmd := splitAndFlat(some)
	testcli.Run(cmd[0], cmd[1:]...)
	if testcli.Failure() {
		exitCode = 1
	}
	return testcli.Stdout(), testcli.Stderr(), exitCode
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

type RunContext struct {
	TPPurl              string
	TPPuser             string
	TPPPassword         string
	TPPZone             string
	CloudUrl            string
	CloudAPIkey         string
	CloudZone           string
	TPPTestingEnabled   bool
	CloudTestingEnabled bool
	FakeTestingEnabled  bool
	TPPIssuerCN           string
	CloudIssuerCN         string
	FakeIssuerCN          string
}

func GetContext() *RunContext {

	c := RunContext{}

	c.TPPurl = os.Getenv("TPPURL")
	c.TPPuser = os.Getenv("TPPUSER")
	c.TPPPassword = os.Getenv("TPPPASSWORD")
	c.TPPZone = os.Getenv("TPPZONE")

	c.CloudUrl = os.Getenv("CLOUDURL")
	c.CloudAPIkey = os.Getenv("CLOUDAPIKEY")
	c.CloudZone = os.Getenv("CLOUDZONE")
	c.TPPTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_TPP_TESTING"))
	c.CloudTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_CLOUD_TESTING"))
	c.FakeTestingEnabled, _ = strconv.ParseBool(os.Getenv("VENAFI_FAKE_TESTING"))
	c.TPPIssuerCN = os.Getenv("TPP_ISSUER_CN")
	c.CloudIssuerCN = os.Getenv("CLOUD_ISSUER_CN")
	c.FakeIssuerCN = os.Getenv("FAKE_ISSUER_CN")

	return &c
}

func sameStringSlice(x, y []string) bool {
	if len(x) != len(y) {
		return false
	}
	// create a map of string -> int
	diff := make(map[string]int, len(x))
	for _, _x := range x {
		// 0 value for int is 0, so just increment a counter for the string
		diff[_x]++
	}
	for _, _y := range y {
		// If the string _y is not in diff bail out early
		if _, ok := diff[_y]; !ok {
			return false
		}
		diff[_y] -= 1
		if diff[_y] == 0 {
			delete(diff, _y)
		}
	}
	if len(diff) == 0 {
		return true
	}
	return false
}
