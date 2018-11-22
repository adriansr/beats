package v1

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	ProtocolName        = "v1"
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

type ReadHeaderFn func(*bytes.Buffer, net.Addr) (int, time.Time, common.MapStr, error)

type NetflowProtocol struct {
	logger       *logp.Logger
	flowTemplate v9.Template
	version      uint16
	readHeader   ReadHeaderFn
}

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	return NewProtocol(ProtocolID, &template, readV1Header)
}

func NewProtocol(version uint16, template v9.Template, readHeader ReadHeaderFn) registry.Protocol {
	return &NetflowProtocol{
		logger:       logp.NewLogger(fmt.Sprintf("netflow-v%d", version)),
		flowTemplate: template,
		version:      version,
		readHeader:   readHeader,
	}
}

func (p *NetflowProtocol) ID() uint16 {
	return p.version
}

func (NetflowProtocol) Start() error {
	return nil
}

func (NetflowProtocol) Stop() error {
	return nil
}

func (p *NetflowProtocol) OnPacket(data []byte, source net.Addr) (flows []flow.Flow) {
	buf := bytes.NewBuffer(data)
	// TODO: count
	numFlows, timestamp, metadata, err := p.readHeader(buf, source)
	if err != nil {
		p.logger.Errorf("Failed parsing packet of %d bytes: %v", len(data), err)
		return nil
	}
	flows, err = p.flowTemplate.Apply(buf, numFlows)
	for i := range flows {
		flows[i].Exporter = metadata
		flows[i].Timestamp = timestamp
	}
	return flows
}

type PacketHeader struct {
	Version   uint16
	Count     uint16
	SysUptime uint32    // 32 bit milliseconds
	Timestamp time.Time // 32 bit seconds + 32 bit nanoseconds
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
		SysUptime: binary.BigEndian.Uint32(arr[4:8]),
		Timestamp: time.Unix(int64(timestamp>>32), int64(timestamp&(1<<32-1))).UTC(),
	}
	return header, nil
}

func readV1Header(buf *bytes.Buffer, source net.Addr) (count int, ts time.Time, metadata common.MapStr, err error) {
	header, err := ReadPacketHeader(buf)
	if err != nil {
		return count, ts, metadata, err
	}
	count = int(header.Count)
	metadata = common.MapStr{
		"version":      uint64(header.Version),
		"timestamp":    header.Timestamp,
		"uptimeMillis": uint64(header.SysUptime),
		"address":      source.String(),
	}
	return count, header.Timestamp, metadata, nil
}
