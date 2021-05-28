package main

import (
	"fmt"
	"os"

	"github.com/elastic/go-libaudit/v2"
)

func main() {
	for i := 0; ; i++ {
		fmt.Printf("- %d\r", i)
		cli, err := libaudit.NewAuditClient(nil)
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
