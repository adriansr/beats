package v1

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
	assert.Equal(t, uint16(1), proto.ID())
	assert.Nil(t, proto.Stop())
}

func TestNetflowProtocol_OnPacket(t *testing.T) {
	proto := New()

	rawS := "00010002000000015bf689f605946fb0" +
		"acd910e5c0a8017b00000000000000000000000e00002cfa" +
		"fff609a0fff6109601bbd711000006001800000000000000" +
		"c0a8017bacd910e500000000000000000000000700000c5b" +
		"fff609a0fff61096d71101bb000006001800000000000000"

	captureTime, err := time.Parse(time.RFC3339Nano, "2018-11-22T10:50:30.093614Z")
	captureTime = captureTime.UTC()
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	expected := []flow.Flow{
		{Timestamp: captureTime,
			Fields: common.MapStr{
				"destinationIPv4Address":   net.ParseIP("192.168.1.123"),
				"destinationTransportPort": uint64(55057),
				"egressInterface":          uint64(0),
				"flowEndSysUpTime":         uint64(4294316182),
				"flowStartSysUpTime":       uint64(4294314400),
				"ingressInterface":         uint64(0),
				"ipClassOfService":         uint64(0),
				"ipNextHopIPv4Address":     net.ParseIP("0.0.0.0"),
				"octetDeltaCount":          uint64(11514),
				"packetDeltaCount":         uint64(14),
				"protocolIdentifier":       uint64(6),
				"sourceIPv4Address":        net.ParseIP("172.217.16.229"),
				"sourceTransportPort":      uint64(443),
				"tcpControlBits":           uint64(24),
				"type":                     "flow",
			},
			Exporter: common.MapStr{
				"address":      "127.0.0.1:59707",
				"timestamp":    captureTime,
				"uptimeMillis": uint64(1),
				"version":      uint64(1),
			},
		}, {
			Timestamp: captureTime,
			Fields: common.MapStr{
				"destinationIPv4Address":   net.ParseIP("172.217.16.229"),
				"destinationTransportPort": uint64(443),
				"egressInterface":          uint64(0),
				"flowEndSysUpTime":         uint64(4294316182),
				"flowStartSysUpTime":       uint64(4294314400),
				"ingressInterface":         uint64(0),
				"ipClassOfService":         uint64(0),
				"ipNextHopIPv4Address":     net.ParseIP("0.0.0.0"),
				"octetDeltaCount":          uint64(3163),
				"packetDeltaCount":         uint64(7),
				"protocolIdentifier":       uint64(6),
				"sourceIPv4Address":        net.ParseIP("192.168.1.123"),
				"sourceTransportPort":      uint64(55057),
				"tcpControlBits":           uint64(24),
				"type":                     "flow",
			},
			Exporter: common.MapStr{
				"address":      "127.0.0.1:59707",
				"timestamp":    captureTime,
				"uptimeMillis": uint64(1),
				"version":      uint64(1),
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

	rawS := "00010002000000015bf689f605"
	raw, err := hex.DecodeString(rawS)
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	flows := proto.OnPacket(raw, test.MakeAddress(t, "127.0.0.1:59707"))
	assert.Len(t, flows, 0)
}

func TestTemplate(t *testing.T) {
	test.ValidateTemplate(t, template)
}
