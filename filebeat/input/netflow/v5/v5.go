package v5

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	template2 "github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/filebeat/input/netflow/v1"
	"github.com/elastic/beats/libbeat/common"
)

const (
	ProtocolName        = "v5"
	ProtocolID   uint16 = 5
)

var template = template2.RecordTemplate{
	ID: 0,
	Fields: []template2.FieldTemplate{
		{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
		{Length: 4, Info: &fields.Field{Name: "destinationIPv4Address", Decoder: fields.Ipv4Address}},
		{Length: 4, Info: &fields.Field{Name: "ipNextHopIPv4Address", Decoder: fields.Ipv4Address}},
		{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
		{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
		{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
		{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
		{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
		{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
		{Length: 2, Info: &fields.Field{Name: "sourceTransportPort", Decoder: fields.Unsigned16}},
		{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
		{Length: 1, Info: &fields.Field{Decoder: fields.Unsigned8}}, // Padding
		{Length: 1, Info: &fields.Field{Name: "tcpControlBits", Decoder: fields.Unsigned16}},
		{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
		{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
		{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
		{Length: 1, Info: &fields.Field{Name: "sourceIPv4PrefixLength", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "destinationIPv4PrefixLength", Decoder: fields.Unsigned8}},
		{Length: 2, Info: &fields.Field{Decoder: fields.Unsigned16}}, // Padding
	},
	TotalLength: 48,
}

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	return v1.NewProtocol(ProtocolID, &template, ReadV5Header)
}

type PacketHeader struct {
	Version          uint16
	Count            uint16
	SysUptime        uint32    // 32 bit milliseconds
	Timestamp        time.Time // 32 bit seconds + 32 bit nanoseconds
	FlowSequence     uint32
	EngineType       uint8
	EngineID         uint8
	SamplingInterval uint16
}

func ReadPacketHeader(buf *bytes.Buffer) (header PacketHeader, err error) {
	var arr [24]byte
	if n, err := buf.Read(arr[:]); err != nil || n != len(arr) {
		return header, err
	}
	timestamp := binary.BigEndian.Uint64(arr[8:16])
	header = PacketHeader{
		Version:          binary.BigEndian.Uint16(arr[:2]),
		Count:            binary.BigEndian.Uint16(arr[2:4]),
		SysUptime:        binary.BigEndian.Uint32(arr[4:8]),
		Timestamp:        time.Unix(int64(timestamp>>32), int64(timestamp&(1<<32-1))).UTC(),
		FlowSequence:     binary.BigEndian.Uint32(arr[16:20]),
		EngineType:       arr[20],
		EngineID:         arr[21],
		SamplingInterval: binary.BigEndian.Uint16(arr[22:]),
	}
	return header, nil
}

func ReadV5Header(buf *bytes.Buffer, source net.Addr) (count int, ts time.Time, metadata common.MapStr, err error) {
	header, err := ReadPacketHeader(buf)
	if err != nil {
		return count, ts, metadata, err
	}
	count = int(header.Count)
	metadata = common.MapStr{
		"version":          uint64(header.Version),
		"timestamp":        header.Timestamp,
		"uptimeMillis":     uint64(header.SysUptime),
		"address":          source.String(),
		"engineType":       uint64(header.EngineType),
		"engineId":         uint64(header.EngineID),
		"samplingInterval": uint64(header.SamplingInterval),
	}
	return count, header.Timestamp, metadata, nil
}
