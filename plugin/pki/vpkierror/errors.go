package vpkierror

import "fmt"

type VCertError struct{ error }
type CertEntryNotFound struct {
	VCertError
	EntryPath string
}

func (e CertEntryNotFound) Error() string {
	return fmt.Sprintf("no entry found in path %s", e.EntryPath)
}
