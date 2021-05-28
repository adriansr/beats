package main

import (
	"fmt"
	"os"
	"strconv"
	"syscall"

	"github.com/elastic/go-libaudit/v2"
)

func main() {
	count := -1
	if len(os.Args) > 1 {
		var err error
		if count, err = strconv.Atoi(os.Args[1]); err != nil {
			fmt.Fprintf(os.Stderr, "Failed to parse count argument '%s': %v\n", os.Args[1], err)
			os.Exit(3)
		}
	}
	cli, err := libaudit.NewAuditClient(os.Stdout)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Connect to audit failed: %v\n", err)
		os.Exit(1)
	}
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(1111 /*User message*/),
			Flags: 0, // Req or Flags?
		},
		Data: []byte("XXX HELLO WORLD! XXX"),
	}
	for count == -1 || count > 0 {
		if _, err := cli.Netlink.Send(msg); err != nil {
			fmt.Fprintf(os.Stderr, "Write error: %v", err)
			os.Exit(2)
		}
		if count > 0 {
			count--
		}
	}
}
