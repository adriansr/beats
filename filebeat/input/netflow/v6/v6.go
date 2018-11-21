package v6

import (
	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/input/netflow/v1"
	"github.com/elastic/beats/filebeat/input/netflow/v5"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
)

const (
	ProtocolName        = "v6"
	ProtocolID   uint16 = 6
)

var template = v9.RecordTemplate{
	ID: 0,
	Fields: []v9.FieldTemplate{
		{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
		{Length: 4, Info: &fields.Field{Name: "destinationIPv4Address", Decoder: fields.Ipv4Address}},
		{Length: 4, Info: &fields.Field{Name: "ipNextHopIPv4Address", Decoder: fields.Ipv4Address}},
		{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned16}},
		{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned16}},
		{Length: 4, Info: &fields.Field{Name: "packetTotalCount", Decoder: fields.Unsigned32}},
		{Length: 4, Info: &fields.Field{Name: "octetTotalCount", Decoder: fields.Unsigned32}},
		{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
		{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
		{Length: 2, Info: &fields.Field{Name: "sourceTransportPort", Decoder: fields.Unsigned16}},
		{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
		{Length: 1, Info: &fields.Field{Decoder: fields.Unsigned8}}, // Padding
		{Length: 1, Info: &fields.Field{Name: "tcpControlBits", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
		{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned16}},
		{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned16}},
		{Length: 1, Info: &fields.Field{Name: "sourceIPv4PrefixLength", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "destinationIPv4PrefixLength", Decoder: fields.Unsigned8}},
		{Length: 6, Info: &fields.Field{Decoder: fields.OctetArray}}, // Padding
	},
	TotalLength: 52,
}

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	return v1.NewProtocol(ProtocolID, &template, v5.ReadV5Header)
}
