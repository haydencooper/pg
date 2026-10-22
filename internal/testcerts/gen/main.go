// gen writes a throwaway authority and a certificate for localhost into the directory it's given, for
// scripts/pg-test.sh. the certificate names localhost only, so a session to 127.0.0.1 shows a host check failing
package main

import (
	"fmt"
	"os"

	"github.com/haydencooper/pg/internal/testcerts"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: gen <dir>")
		os.Exit(2)
	}
	s, err := testcerts.New("localhost")
	if err == nil {
		err = s.Write(os.Args[1])
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
