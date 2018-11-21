package v1

import (
	"bytes"
	"encoding/binary"
	"net"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	ProtocolName        = "v1"
	LogSelector         = "netflow-v1"
	ProtocolID   uint16 = 1
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
		{Length: 2, Info: &fields.Field{Decoder: fields.Unsigned16}}, // Padding
		{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
		{Length: 1, Info: &fields.Field{Name: "tcpControlBits", Decoder: fields.Unsigned8}},
		{Length: 7, Info: &fields.Field{Decoder: fields.OctetArray}}, // Padding
	},
	TotalLength: 48,
}

type NetflowV5Protocol struct {
	logger *logp.Logger
}

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	return &NetflowV5Protocol{
		logger: logp.NewLogger(LogSelector),
	}
}

func (NetflowV5Protocol) ID() uint16 {
	return ProtocolID
}

func (NetflowV5Protocol) Start() error {
	return nil
}

func (NetflowV5Protocol) Stop() error {
	return nil
}

func (p NetflowV5Protocol) OnPacket(data []byte, source net.Addr) (flows []flow.Flow) {
	buf := bytes.NewBuffer(data)
	header, err := ReadPacketHeader(buf)
	if err != nil {
		p.logger.Errorf("Failed parsing packet of %d bytes: %v", len(data), err)
		return nil
	}
	if header.Count < 1 || header.Count > 32 {
		return nil
	}
	//p.logger.Infof("Received packet of %d bytes: %+v", len(data), header)
	flows, err = template.Apply(buf)
	for i := range flows {
		flows[i].Timestamp = header.Timestamp
	}
	return flows
}

type PacketHeader struct {
	Version   uint16
	Count     uint16
	SysUptime time.Duration // 32 bit milliseconds
	Timestamp time.Time     // 32 bit seconds + 32 bit nanoseconds
}

func ReadPacketHeader(buf *bytes.Buffer) (header PacketHeader, err error) {
	var arr [16]byte
	if n, err := buf.Read(arr[:]); err != nil || n != len(arr) {
		return header, err
	}
	timestamp := binary.BigEndian.Uint64(arr[8:16])
	header = PacketHeader{
		Version:   binary.BigEndian.Uint16(arr[:2]),
		Count:     binary.BigEndian.Uint16(arr[2:4]),
		SysUptime: time.Duration(binary.BigEndian.Uint32(arr[4:8])) * time.Millisecond,
		Timestamp: time.Unix(int64(timestamp>>32), int64(timestamp&(1<<32-1))),
	}
	return header, nil
}
