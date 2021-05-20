package decoder

import (
	"bytes"
	"net"
	"os"
	"sync"
	"time"

	"github.com/elastic/beats/v7/x-pack/filebeat/input/netflow/decoder/config"
)

var initOnce sync.Once
var decoder *Decoder
var source = net.TCPAddr{
	IP:   net.ParseIP("127.0.0.1"),
	Port: 1234,
}

func Fuzz(data []byte) int {
	initOnce.Do(func() {
		var err error
		def := config.Defaults()
		var cfg = &def
		cfg = cfg.WithExpiration(time.Duration(0)).
			WithLogOutput(os.Stderr).
			WithSequenceResetEnabled(false).
			WithProtocols("v9", "ipfix")
		if decoder, err = NewDecoder(cfg); err != nil {
			panic(err)
		}
	})
	if _, err := decoder.Read(bytes.NewBuffer(data), &source); err != nil {
		return 0
	}
	return 1
}
