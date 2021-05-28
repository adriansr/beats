package main

import (
	"fmt"
	"os"

	"github.com/elastic/go-libaudit/v2"
)

func main() {
	for {
		cli, err := libaudit.NewAuditClient(os.Stdout)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Connect to audit failed: %v\n", err)
			os.Exit(1)
		}
		if err = cli.SetPID(libaudit.WaitForReply); err != nil {
			fmt.Fprintf(os.Stderr, "SetPID: %v\n", err)
		}
		if err = cli.Close(); err != nil {
			fmt.Fprintf(os.Stderr, "Close: %v\n", err)
		}
	}
}
