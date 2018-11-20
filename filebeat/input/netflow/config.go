// License: TODO

package netflow

import (
	"time"

	"github.com/dustin/go-humanize"
	"github.com/elastic/beats/filebeat/input/netflow/ipfix"
	"github.com/elastic/beats/filebeat/input/netflow/v9"

	"github.com/elastic/beats/filebeat/harvester"
	"github.com/elastic/beats/filebeat/inputsource/udp"
)

var defaultConfig = config{
	Config: udp.Config{
		MaxMessageSize: 64 * humanize.KiByte,
		// TODO: What should be default port?
		Host: "0.0.0.0:9995",
		// TODO: What should be the default timeout?
		// TODO: What is this timeout used for?
		Timeout: time.Minute * 5,
	},
	ForwarderConfig: harvester.ForwarderConfig{
		// TODO: Is this type=udp or type=my_input?
		Type: InputName,
	},
	Protocols: []string{v9.ProtocolName, ipfix.ProtocolName},
}

type config struct {
	udp.Config                `config:",inline"`
	harvester.ForwarderConfig `config:",inline"`
	Protocols                 []string `config:"protocols"`
}
