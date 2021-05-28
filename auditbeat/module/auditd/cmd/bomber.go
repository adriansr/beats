package cmd

import (
	"fmt"
	"os"
	"syscall"

	"github.com/elastic/go-libaudit/v2"
)

func main() {
	cli, err := libaudit.NewAuditClient(os.Stdout)
	if err != nil {
		panic(err)
	}
	msg := syscall.NetlinkMessage{
		Header: syscall.NlMsghdr{
			Type:  uint16(1111 /*User message*/),
			Flags: 0, // Req or Flags?
		},
		Data: []byte("XXX HELLO WORLD! XXX"),
	}
	if _, err := cli.Netlink.Send(msg); err != nil {
		fmt.Fprintf(os.Stderr, "Write error: %v", err)
	}
}
