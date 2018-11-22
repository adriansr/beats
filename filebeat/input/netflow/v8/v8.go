// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package v8

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	ProtocolName        = "v8"
	LogSelector         = "netflow-v8"
	ProtocolID   uint16 = 8
)

// Type of Netflow V8 flow records
// See https://www.cisco.com/c/en/us/td/docs/net_mgmt/netflow_collection_engine/3-6/user/guide/format.html
const (
	RouterAS uint8 = iota + 1
	RouterProtoPort
	RouterSrcPrefix
	RouterDstPrefix
	RouterPrefix
	DestOnly
	SrcDst
	FullFlow
	TosAS
	TosProtoPort
	TosSrcPrefix
	TosDstPrefix
	TosPrefix
	PrePortProtocol
)

var templates = map[uint8]template.RecordTemplate{
	RouterAS: {
		Fields: []template.FieldTemplate{
			//  observedFlowTotalCount
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
		},
		TotalLength: 28,
	},
	RouterProtoPort: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
			{Length: 3, Info: &fields.Field{Decoder: fields.OctetArray}},
			{Length: 2, Info: &fields.Field{Name: "sourceTransportPort", Decoder: fields.Unsigned16}},
			{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
		},
		TotalLength: 28,
	},
	RouterDstPrefix: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
			{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
		},
		TotalLength: 32,
	},
	RouterSrcPrefix: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
			{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
		},
		TotalLength: 32,
	},
	RouterPrefix: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Decoder: fields.OctetArray}},
			{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
		},
		TotalLength: 40,
	},
	TosAS: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 3, Info: &fields.Field{Decoder: fields.OctetArray}},
		},
		TotalLength: 32,
	},
	TosProtoPort: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
			{Length: 2, Info: &fields.Field{Name: "sourceTransportPort", Decoder: fields.Unsigned16}},
			{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
		},
		TotalLength: 32,
	},
	PrePortProtocol: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Prefix", Decoder: fields.Ipv4Address}},
			// Warning: according to CISCO docs, this is reversed (dest, src)
			{Length: 1, Info: &fields.Field{Name: "destinationIPv4PrefixLength", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "sourceIPv4PrefixLength", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
			{Length: 2, Info: &fields.Field{Name: "sourceTransportPort", Decoder: fields.Unsigned16}},
			{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
		},
		TotalLength: 40,
	},
	TosSrcPrefix: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 1, Info: &fields.Field{Name: "sourceIPv4PrefixLength", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
		},
		TotalLength: 32,
	},
	TosDstPrefix: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 1, Info: &fields.Field{Name: "destinationIPv4PrefixLength", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Decoder: fields.OctetArray}},
		},
		TotalLength: 32,
	},
	TosPrefix: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "deltaFlowCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Prefix", Decoder: fields.Ipv4Address}},
			{Length: 1, Info: &fields.Field{Name: "destinationIPv4PrefixLength", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "sourceIPv4PrefixLength", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Decoder: fields.Unsigned8}},
			{Length: 2, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "bgpDestinationAsNumber", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
		},
		TotalLength: 40,
	},
	DestOnly: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Address", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			// Warning: This is documented as "marked_tos: Type of Service of the packets that exceeded the contract"
			//          but I can't find a V9 field for it.
			{Length: 1, Info: &fields.Field{Name: "postIpClassOfService", Decoder: fields.Unsigned8}},
			// Warning: This is documented as "extraPkts: Packets that exceeded the contract"
			//          but I can't find a V9 field for it.
			{Length: 4, Info: &fields.Field{Name: "droppedPacketDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "ipv4RouterSc", Decoder: fields.Ipv4Address}},
		},
		TotalLength: 32,
	},
	SrcDst: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Address", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},
			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			// Warning: This is documented as "marked_tos: Type of Service of the packets that exceeded the contract"
			//          but I can't find a V9 field for it.
			{Length: 1, Info: &fields.Field{Name: "postIpClassOfService", Decoder: fields.Unsigned8}},
			{Length: 2, Info: &fields.Field{Decoder: fields.Unsigned16}}, // Padding
			// Warning: This is documented as "extraPkts: Packets that exceeded the contract"
			//          but I can't find a V9 field for it.
			{Length: 4, Info: &fields.Field{Name: "droppedPacketDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "ipv4RouterSc", Decoder: fields.Ipv4Address}},
		},
		TotalLength: 40,
	},
	FullFlow: {
		Fields: []template.FieldTemplate{
			{Length: 4, Info: &fields.Field{Name: "destinationIPv4Address", Decoder: fields.Ipv4Address}},
			{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
			{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
			{Length: 2, Info: &fields.Field{Name: "sourceTransportPort", Decoder: fields.Unsigned16}},
			{Length: 4, Info: &fields.Field{Name: "packetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "flowStartSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 4, Info: &fields.Field{Name: "flowEndSysUpTime", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
			{Length: 2, Info: &fields.Field{Name: "ingressInterface", Decoder: fields.Unsigned32}},

			{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Name: "protocolIdentifier", Decoder: fields.Unsigned8}},
			// Warning: This is documented as "marked_tos: Type of Service of the packets that exceeded the contract"
			//          but I can't find a V9 field for it.
			{Length: 1, Info: &fields.Field{Name: "postIpClassOfService", Decoder: fields.Unsigned8}},
			{Length: 1, Info: &fields.Field{Decoder: fields.Unsigned8}}, // Padding
			// Warning: This is documented as "extraPkts: Packets that exceeded the contract"
			//          but I can't find a V9 field for it.
			{Length: 4, Info: &fields.Field{Name: "droppedPacketDeltaCount", Decoder: fields.Unsigned64}},
			{Length: 4, Info: &fields.Field{Name: "ipv4RouterSc", Decoder: fields.Ipv4Address}},
		},
		TotalLength: 44,
	},
}

type NetflowV8Protocol struct {
	logger *logp.Logger
}

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	return &NetflowV8Protocol{
		logger: logp.NewLogger(LogSelector),
	}
}

func (NetflowV8Protocol) ID() uint16 {
	return ProtocolID
}

func (p *NetflowV8Protocol) OnPacket(data []byte, source net.Addr) (flows []record.Record) {
	buf := bytes.NewBuffer(data)
	header, err := ReadPacketHeader(buf)
	if err != nil {
		p.logger.Errorf("Failed parsing packet of %d bytes: %v", len(data), err)
		return nil
	}
	template, found := templates[header.Aggregation]
	if !found {
		p.logger.Errorf("Packet from %s uses an unknown V8 aggregation: %d", source, header.Aggregation)
		return nil
	}
	metadata := header.GetMetadata(source)
	flows, err = template.Apply(buf, int(header.Count))
	for i := range flows {
		flows[i].Exporter = metadata
		flows[i].Timestamp = header.Timestamp
	}
	return flows
}

func (NetflowV8Protocol) Start() error {
	return nil
}

func (NetflowV8Protocol) Stop() error {
	return nil
}

type PacketHeader struct {
	Version      uint16
	Count        uint16
	SysUptime    uint32    // 32 bit milliseconds
	Timestamp    time.Time // 32 bit seconds + 32 bit nanoseconds
	FlowSequence uint32
	EngineType   uint8
	EngineID     uint8
	Aggregation  uint8
	AggVersion   uint8
	Reserved     uint32
}

func ReadPacketHeader(buf *bytes.Buffer) (header PacketHeader, err error) {
	var arr [28]byte
	if n, err := buf.Read(arr[:]); err != nil || n != len(arr) {
		if err == nil {
			err = io.EOF
		}
		return header, err
	}
	timestamp := binary.BigEndian.Uint64(arr[8:16])
	header = PacketHeader{
		Version:      binary.BigEndian.Uint16(arr[:2]),
		Count:        binary.BigEndian.Uint16(arr[2:4]),
		SysUptime:    binary.BigEndian.Uint32(arr[4:8]),
		Timestamp:    time.Unix(int64(timestamp>>32), int64(timestamp&(1<<32-1))).UTC(),
		FlowSequence: binary.BigEndian.Uint32(arr[16:20]),
		EngineType:   arr[20],
		EngineID:     arr[21],
		Aggregation:  arr[22],
		AggVersion:   arr[23],
	}
	return header, nil
}

func (header PacketHeader) GetMetadata(source net.Addr) common.MapStr {
	return common.MapStr{
		"version":            uint64(header.Version),
		"timestamp":          header.Timestamp,
		"uptimeMillis":       uint64(header.SysUptime),
		"address":            source.String(),
		"engineType":         uint64(header.EngineType),
		"engineId":           uint64(header.EngineID),
		"aggregation":        uint64(header.Aggregation),
		"aggregationVersion": uint64(header.AggVersion),
	}
}
