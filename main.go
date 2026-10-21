// Command obrien is a security-focused reverse HTTP proxy daemon. It accepts
// cleartext HTTP and/or terminates TLS, and forwards requests to a single
// upstream where they can be monitored and filtered.
//
// Process management (start, stop, metrics, ...) is provided by kettlingar.
package main

import (
	"net/http"
	"os"

	"github.com/mailpile/kettlingar-go/kettlingar"
)

const serviceName = "obrien"

func main() {
	svc := &Obrien{}
	ks := kettlingar.MakeService(serviceName, "", http.NewServeMux(), svc)
	if ks == nil {
		os.Exit(1)
	}
	ks.DefaultMain(os.Args[0], os.Args[1:])
}
