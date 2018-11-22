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
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/filebeat/input/netflow/test"
	"github.com/elastic/beats/libbeat/common"
	"github.com/stretchr/testify/assert"
)

func TestTemplates(t *testing.T) {
	for code, template := range templates {
		if !test.ValidateTemplate(t, template) {
			t.Fatal("Failed validating template for V8 record", code)
		}
	}
}

func TestNetflowProtocol_New(t *testing.T) {
	proto := New()

	assert.Nil(t, proto.Start())
	assert.Equal(t, uint16(8), proto.ID())
	assert.Nil(t, proto.Stop())
}

func TestNetflowProtocol_BadPacket(t *testing.T) {
	proto := New()

	rawS := "00080002000000015bf689f605"
	raw, err := hex.DecodeString(rawS)
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	flows := proto.OnPacket(raw, test.MakeAddress(t, "127.0.0.1:59707"))
	assert.Len(t, flows, 0)
}

func TestNetflowV8Protocol_OnPacket(t *testing.T) {
	proto := New()
	address := test.MakeAddress(t, "127.0.0.1:11111")
	captureTime, err := time.Parse(time.RFC3339Nano, "2018-11-22T20:53:03.987654321Z")
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	for _, testCase := range []struct {
		name        string
		aggregation uint8
		packet      []uint16
		expected    flow.Flow
	}{
		{
			name:        "RouterAS",
			aggregation: RouterAS,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                   "flow",
					"deltaFlowCount":         uint64(0x12345678),
					"packetDeltaCount":       uint64(0x9abcdef),
					"octetDeltaCount":        uint64(0x11223344),
					"flowStartSysUpTime":     uint64(0x55667788),
					"flowEndSysUpTime":       uint64(0x99aa99bb),
					"bgpSourceAsNumber":      uint64(0x1111),
					"bgpDestinationAsNumber": uint64(0x2222),
					"ingressInterface":       uint64(0x3333),
					"egressInterface":        uint64(0x4444),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(RouterAS),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "RouterProtoPort",
			aggregation: RouterProtoPort,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                     "flow",
					"deltaFlowCount":           uint64(0x12345678),
					"packetDeltaCount":         uint64(0x9abcdef),
					"octetDeltaCount":          uint64(0x11223344),
					"flowStartSysUpTime":       uint64(0x55667788),
					"flowEndSysUpTime":         uint64(0x99aa99bb),
					"protocolIdentifier":       uint64(0x11),
					"sourceTransportPort":      uint64(0x3333),
					"destinationTransportPort": uint64(0x4444),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(RouterProtoPort),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "RouterDstPrefix",
			aggregation: RouterDstPrefix,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x0506, 0,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                   "flow",
					"deltaFlowCount":         uint64(0x12345678),
					"packetDeltaCount":       uint64(0x09abcdef),
					"octetDeltaCount":        uint64(0x11223344),
					"flowStartSysUpTime":     uint64(0x55667788),
					"flowEndSysUpTime":       uint64(0x99aa99bb),
					"destinationIPv4Prefix":  net.ParseIP("17.17.34.34"),
					"bgpDestinationAsNumber": uint64(0x4444),
					"egressInterface":        uint64(0x0506),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(RouterDstPrefix),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "RouterSrcPrefix",
			aggregation: RouterSrcPrefix,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x0506, 0,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":               "flow",
					"deltaFlowCount":     uint64(0x12345678),
					"packetDeltaCount":   uint64(0x09abcdef),
					"octetDeltaCount":    uint64(0x11223344),
					"flowStartSysUpTime": uint64(0x55667788),
					"flowEndSysUpTime":   uint64(0x99aa99bb),
					"sourceIPv4Prefix":   net.ParseIP("17.17.34.34"),
					"bgpSourceAsNumber":  uint64(0x4444),
					"ingressInterface":   uint64(0x0506),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(RouterSrcPrefix),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "RouterPrefix",
			aggregation: RouterPrefix,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0, 0,
				0x0506, 0x0708, 0x090a, 0x0b0c, 0x0d0e,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                   "flow",
					"deltaFlowCount":         uint64(0x12345678),
					"packetDeltaCount":       uint64(0x9abcdef),
					"octetDeltaCount":        uint64(0x11223344),
					"flowStartSysUpTime":     uint64(0x55667788),
					"flowEndSysUpTime":       uint64(0x99aa99bb),
					"sourceIPv4Prefix":       net.ParseIP("17.17.34.34"),
					"destinationIPv4Prefix":  net.ParseIP("51.51.68.68"),
					"bgpSourceAsNumber":      uint64(0x0506),
					"bgpDestinationAsNumber": uint64(0x0708),
					"ingressInterface":       uint64(0x090a),
					"egressInterface":        uint64(0x0b0c),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(RouterPrefix),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "TosAS",
			aggregation: TosAS,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                   "flow",
					"deltaFlowCount":         uint64(0x12345678),
					"packetDeltaCount":       uint64(0x09abcdef),
					"octetDeltaCount":        uint64(0x11223344),
					"flowStartSysUpTime":     uint64(0x55667788),
					"flowEndSysUpTime":       uint64(0x99aa99bb),
					"bgpSourceAsNumber":      uint64(0x1111),
					"bgpDestinationAsNumber": uint64(0x2222),
					"ingressInterface":       uint64(0x3333),
					"egressInterface":        uint64(0x4444),
					"ipClassOfService":       uint64(0x55),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(TosAS),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "TosProtoPort",
			aggregation: TosProtoPort,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                     "flow",
					"deltaFlowCount":           uint64(0x12345678),
					"packetDeltaCount":         uint64(0x9abcdef),
					"octetDeltaCount":          uint64(0x11223344),
					"flowStartSysUpTime":       uint64(0x55667788),
					"flowEndSysUpTime":         uint64(0x99aa99bb),
					"protocolIdentifier":       uint64(0x11),
					"ipClassOfService":         uint64(0x11),
					"sourceTransportPort":      uint64(0x3333),
					"destinationTransportPort": uint64(0x4444),
					"ingressInterface":         uint64(0x5555),
					"egressInterface":          uint64(0x6666),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(TosProtoPort),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "PrePortProtocol",
			aggregation: PrePortProtocol,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
				0x7181, 0x91a1, 0xb1c1, 0xd1e1,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                        "flow",
					"deltaFlowCount":              uint64(0x12345678),
					"packetDeltaCount":            uint64(0x9abcdef),
					"octetDeltaCount":             uint64(0x11223344),
					"flowStartSysUpTime":          uint64(0x55667788),
					"flowEndSysUpTime":            uint64(0x99aa99bb),
					"sourceIPv4Prefix":            net.ParseIP("17.17.34.34"),
					"destinationIPv4Prefix":       net.ParseIP("51.51.68.68"),
					"destinationIPv4PrefixLength": uint64(0x55),
					"sourceIPv4PrefixLength":      uint64(0x55),
					"ipClassOfService":            uint64(0x66),
					"protocolIdentifier":          uint64(0x66),
					"sourceTransportPort":         uint64(0x7181),
					"destinationTransportPort":    uint64(0x91a1),
					"ingressInterface":            uint64(0xb1c1),
					"egressInterface":             uint64(0xd1e1),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(PrePortProtocol),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "TosSrcPrefix",
			aggregation: TosSrcPrefix,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                   "flow",
					"deltaFlowCount":         uint64(0x12345678),
					"packetDeltaCount":       uint64(0x9abcdef),
					"octetDeltaCount":        uint64(0x11223344),
					"flowStartSysUpTime":     uint64(0x55667788),
					"flowEndSysUpTime":       uint64(0x99aa99bb),
					"sourceIPv4Prefix":       net.ParseIP("17.17.34.34"),
					"sourceIPv4PrefixLength": uint64(0x33),
					"ipClassOfService":       uint64(0x33),
					"bgpSourceAsNumber":      uint64(0x4444),
					"ingressInterface":       uint64(0x5555),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(TosSrcPrefix),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "TosDstPrefix",
			aggregation: TosDstPrefix,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                        "flow",
					"deltaFlowCount":              uint64(0x12345678),
					"packetDeltaCount":            uint64(0x9abcdef),
					"octetDeltaCount":             uint64(0x11223344),
					"flowStartSysUpTime":          uint64(0x55667788),
					"flowEndSysUpTime":            uint64(0x99aa99bb),
					"destinationIPv4Prefix":       net.ParseIP("17.17.34.34"),
					"destinationIPv4PrefixLength": uint64(0x33),
					"ipClassOfService":            uint64(0x33),
					"bgpDestinationAsNumber":      uint64(0x4444),
					"egressInterface":             uint64(0x5555),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(TosDstPrefix),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "TosPrefix",
			aggregation: TosPrefix,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
				0x7181, 0x91a1, 0xb1c1, 0xd1e1,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type":                        "flow",
					"deltaFlowCount":              uint64(0x12345678),
					"packetDeltaCount":            uint64(0x9abcdef),
					"octetDeltaCount":             uint64(0x11223344),
					"flowStartSysUpTime":          uint64(0x55667788),
					"flowEndSysUpTime":            uint64(0x99aa99bb),
					"sourceIPv4Prefix":            net.ParseIP("17.17.34.34"),
					"destinationIPv4Prefix":       net.ParseIP("51.51.68.68"),
					"destinationIPv4PrefixLength": uint64(0x55),
					"sourceIPv4PrefixLength":      uint64(0x55),
					"ipClassOfService":            uint64(0x66),
					"bgpSourceAsNumber":           uint64(0x7181),
					"bgpDestinationAsNumber":      uint64(0x91a1),
					"ingressInterface":            uint64(0xb1c1),
					"egressInterface":             uint64(0xd1e1),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(TosPrefix),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "DestOnly",
			aggregation: DestOnly,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type": "flow",
					"destinationIPv4Address":  net.ParseIP("18.52.86.120"),
					"packetDeltaCount":        uint64(0x9abcdef),
					"octetDeltaCount":         uint64(0x11223344),
					"flowStartSysUpTime":      uint64(0x55667788),
					"flowEndSysUpTime":        uint64(0x99aa99bb),
					"egressInterface":         uint64(0x1111),
					"ipClassOfService":        uint64(0x22),
					"postIpClassOfService":    uint64(0x22),
					"droppedPacketDeltaCount": uint64(0x33334444),
					"ipv4RouterSc":            net.ParseIP("85.85.102.102"),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(DestOnly),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "SrcDst",
			aggregation: SrcDst,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
				0x7181, 0x91a1, 0xb1c1, 0xd1e1,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type": "flow",
					"destinationIPv4Address":  net.ParseIP("18.52.86.120"),
					"sourceIPv4Address":       net.ParseIP("9.171.205.239"),
					"packetDeltaCount":        uint64(0x11223344),
					"octetDeltaCount":         uint64(0x55667788),
					"flowStartSysUpTime":      uint64(0x99aa99bb),
					"flowEndSysUpTime":        uint64(0x11112222),
					"egressInterface":         uint64(0x3333),
					"ingressInterface":        uint64(0x4444),
					"ipClassOfService":        uint64(0x55),
					"postIpClassOfService":    uint64(0x55),
					"droppedPacketDeltaCount": uint64(0x718191a1),
					"ipv4RouterSc":            net.ParseIP("177.193.209.225"),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(SrcDst),
					"aggregationVersion": uint64(0),
				},
			},
		},
		{
			name:        "FullFlow",
			aggregation: FullFlow,
			packet: []uint16{
				// Header
				8, 1, 1, 2, 23543, 5935, 15070, 26801, 0x1234, 0x5678, 258, 0, 0, 0,
				// Flow record
				0x1234, 0x5678, 0x09ab, 0xcdef, 0x1122, 0x3344, 0x5566, 0x7788,
				0x99aa, 0x99bb, 0x1111, 0x2222, 0x3333, 0x4444, 0x5555, 0x6666,
				0x7181, 0x91a1, 0xb1c1, 0xd1e1, 0x2f2e, 0x2d2c,
			},
			expected: flow.Flow{
				Timestamp: captureTime,
				Fields: common.MapStr{
					"type": "flow",
					"destinationIPv4Address":   net.ParseIP("18.52.86.120"),
					"sourceIPv4Address":        net.ParseIP("9.171.205.239"),
					"destinationTransportPort": uint64(0x1122),
					"sourceTransportPort":      uint64(0x3344),
					"packetDeltaCount":         uint64(0x55667788),
					"octetDeltaCount":          uint64(0x99aa99bb),
					"flowStartSysUpTime":       uint64(0x11112222),
					"flowEndSysUpTime":         uint64(0x33334444),
					"egressInterface":          uint64(0x5555),
					"ingressInterface":         uint64(0x6666),
					"ipClassOfService":         uint64(0x71),
					"protocolIdentifier":       uint64(0x81),
					"postIpClassOfService":     uint64(0x91),
					"droppedPacketDeltaCount":  uint64(0xb1c1d1e1),
					"ipv4RouterSc":             net.ParseIP("47.46.45.44"),
				},
				Exporter: common.MapStr{
					"version":            uint64(8),
					"timestamp":          captureTime,
					"uptimeMillis":       uint64(0x10002),
					"address":            address.String(),
					"engineType":         uint64(1),
					"engineId":           uint64(2),
					"aggregation":        uint64(FullFlow),
					"aggregationVersion": uint64(0),
				},
			},
		},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			raw := test.MakePacket(testCase.packet)
			raw[22] = testCase.aggregation
			flow := proto.OnPacket(raw, address)
			if !assert.Len(t, flow, 1) {
				return
			}
			t.Logf("fields: %+v", flow[0].Fields)
			test.AssertFlowsEqual(t, testCase.expected, flow[0])
		})
	}
}
