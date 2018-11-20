package ipfix

import (
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	ProtocolName             = "ipfix"
	ProtocolID        uint16 = 10
	TemplateFlowsetID        = 2
	TemplateOptionsID        = 3
)

type IPFixProtocol struct {
	v9.NetflowV9Protocol
}

var _ registry.Protocol = (*IPFixProtocol)(nil)

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	proto := &IPFixProtocol{
		NetflowV9Protocol: *v9.NewProtocolWithDecoder(DecoderIPFix{}, logp.NewLogger(ProtocolName)),
	}
	return proto
}

func (_ IPFixProtocol) ID() uint16 {
	return ProtocolID
}
