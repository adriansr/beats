package v5

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

func TestNetflowProtocol_New(t *testing.T) {
	proto := New()

	assert.Nil(t, proto.Start())
	assert.Equal(t, uint16(5), proto.ID())
	assert.Nil(t, proto.Stop())
}

func TestNetflowProtocol_OnPacket(t *testing.T) {
	proto := New()

	rawS := "00050002000000015bf68d8b35fcb9780000000000000000" +
		"acd910e5c0a8017b00000000000000000000000e00002cfa" +
		"ffe8086cffe80f6201bbd711001806000000000000000000" +
		"c0a8017bacd910e500000000000000000000000700000c5b" +
		"ffe8086cffe80f62d71101bb001806000000000000000000"

	captureTime, err := time.Parse(time.RFC3339Nano, "2018-11-22T11:05:47.905755Z")
	captureTime = captureTime.UTC()
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	expected := []flow.Flow{
		{
			Timestamp: captureTime,
			Fields: common.MapStr{
				"bgpDestinationAsNumber":      uint64(0),
				"bgpSourceAsNumber":           uint64(0),
				"destinationIPv4Address":      net.ParseIP("192.168.1.123"),
				"destinationIPv4PrefixLength": uint64(0),
				"destinationTransportPort":    uint64(55057),
				"egressInterface":             uint64(0),
				"flowEndSysUpTime":            uint64(4293398370),
				"flowStartSysUpTime":          uint64(4293396588),
				"ingressInterface":            uint64(0),
				"ipClassOfService":            uint64(0),
				"ipNextHopIPv4Address":        net.ParseIP("0.0.0.0"),
				"octetTotalCount":             uint64(11514),
				"packetTotalCount":            uint64(14),
				"protocolIdentifier":          uint64(6),
				"sourceIPv4Address":           net.ParseIP("172.217.16.229"),
				"sourceIPv4PrefixLength":      uint64(0),
				"sourceTransportPort":         uint64(443),
				"tcpControlBits":              uint64(24),
				"type":                        "flow",
			},
			Exporter: common.MapStr{
				"address":          "127.0.0.1:59707",
				"engineId":         uint64(0),
				"engineType":       uint64(0),
				"samplingInterval": uint64(0),
				"timestamp":        captureTime,
				"uptimeMillis":     uint64(1),
				"version":          uint64(5),
			},
		}, {
			Timestamp: captureTime,
			Fields: common.MapStr{
				"bgpDestinationAsNumber":      uint64(0),
				"bgpSourceAsNumber":           uint64(0),
				"destinationIPv4Address":      net.ParseIP("172.217.16.229"),
				"destinationIPv4PrefixLength": uint64(0),
				"destinationTransportPort":    uint64(443),
				"egressInterface":             uint64(0),
				"flowEndSysUpTime":            uint64(4293398370),
				"flowStartSysUpTime":          uint64(4293396588),
				"ingressInterface":            uint64(0),
				"ipClassOfService":            uint64(0),
				"ipNextHopIPv4Address":        net.ParseIP("0.0.0.0"),
				"octetTotalCount":             uint64(3163),
				"packetTotalCount":            uint64(7),
				"protocolIdentifier":          uint64(6),
				"sourceIPv4Address":           net.ParseIP("192.168.1.123"),
				"sourceIPv4PrefixLength":      uint64(0),
				"sourceTransportPort":         uint64(55057),
				"tcpControlBits":              uint64(24),
				"type":                        "flow",
			},
			Exporter: common.MapStr{
				"address":          "127.0.0.1:59707",
				"engineId":         uint64(0),
				"engineType":       uint64(0),
				"samplingInterval": uint64(0),
				"timestamp":        captureTime,
				"uptimeMillis":     uint64(1),
				"version":          uint64(5),
			},
		},
	}
	raw, err := hex.DecodeString(rawS)
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	flows := proto.OnPacket(raw, test.MakeAddress(t, "127.0.0.1:59707"))
	assert.Len(t, flows, len(expected))
	assert.Equal(t, expected, flows)
}

func TestNetflowProtocol_BadPacket(t *testing.T) {
	proto := New()

	rawS := "00050002000000015bf689f605"
	raw, err := hex.DecodeString(rawS)
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	flows := proto.OnPacket(raw, test.MakeAddress(t, "127.0.0.1:59707"))
	assert.Len(t, flows, 0)
}
