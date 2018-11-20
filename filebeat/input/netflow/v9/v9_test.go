package v9

import (
	"encoding/binary"
	"encoding/hex"
	"net"
	"testing"
	"time"

	"github.com/elastic/beats/libbeat/logp"
	"github.com/stretchr/testify/assert"
)

func TestNetflowV9Protocol_ID(t *testing.T) {
	assert.Equal(t, NetflowV9ProtocolID, New().ID())
}

func TestFlowsAndTemplatesPacket(t *testing.T) {
	logp.TestingSetup()
	raw := "" +
		"00090012c30bfb2a53e0bd96a5bab7ef000000c8000000900103000900080004" +
		"00e1000400ea00040004000100e600010143000801690002016b0002016c0002" +
		"01020002011b000400e60001010100080008000400e100040007000200e30002" +
		"00ea00040004000100e60001014300080100000c0008000400e10004000c0004" +
		"00e200040007000200e30002000b000200e4000200ea00040004000100e60001" +
		"014300080100021864409c93b906199c42dc981342dc9813d5407bc801bb01bb" +
		"00000000060100000147a5e492e56440a119b90619a15bda7a945bda7a94cf6b" +
		"df600050005000000000060100000147a5e492e564403194b906193102857a86" +
		"02857a86cee4b6741ae11ae100000000060100000147a5e492e564403194b906" +
		"19315f9806435f980643cee2b6751ae21ae200000000060100000147a5e492e5" +
		"6440d968b90619d9b90cf19bb90cf19b041978b0005000500000000006020000" +
		"0147a5e492e564403194b9061931b22f7aa0b22f7aa0cee3b6761ae11ae10000" +
		"0000060100000147a5e492e66440c5c9b90619c557f0a24f57f0a24fa05d1ae0" +
		"0050005000000000060200000147a5e492e664409502b9061995b4041079b404" +
		"107904435a632c792c7900000000110100000147a5e492e664409a67b906199a" +
		"57f087d257f087d2fc393ac20050005000000000060200000147a5e492e66440" +
		"f43bb90619f4adc22081adc22081b2965ac901bb01bb00000000060200000147" +
		"a5e492e66440b926b90619b9563bed27563bed2751a86991c8d5c8d500000000" +
		"110200000147a5e492e66440c62cb90619c6d9765f41d9765f41d3f3d2ce53b1" +
		"53b100000000060200000147a5e492e6644052b2b906195257f5c46a57f5c46a" +
		"979499a00050005000000000060100000147a5e492e664405095b9061950bc2b" +
		"6fa0bc2b6fa0fbfb5c5c587c587c00000000060200000147a5e492e6"
	packet, err := hex.DecodeString(raw)
	assert.NoError(t, err)
	proto := New()
	addr := makeAddr(t, "127.0.0.1:9999")
	flows := proto.OnPacket(packet, addr)
	assert.Len(t, flows, 14)
	eTime, err := time.Parse(time.RFC3339Nano, "2014-08-05T11:18:46.245Z")
	assert.NoError(t, err)

	expected := map[string][]interface{}{
		"destinationIPv4Address":           {net.ParseIP("188.43.111.160"), net.ParseIP("173.194.32.129"), net.ParseIP("178.47.122.160"), net.ParseIP("180.4.16.121"), net.ParseIP("185.12.241.155"), net.ParseIP("2.133.122.134"), net.ParseIP("217.118.95.65"), net.ParseIP("66.220.152.19"), net.ParseIP("86.59.237.39"), net.ParseIP("87.240.135.210"), net.ParseIP("87.240.162.79"), net.ParseIP("87.245.196.106"), net.ParseIP("91.218.122.148"), net.ParseIP("95.152.6.67")},
		"destinationTransportPort":         {uint64(22652), uint64(443), uint64(11385), uint64(21425), uint64(51413), uint64(6881), uint64(6882), uint64(80)},
		"ingressVRFID":                     {uint64(0)},
		"natEvent":                         {uint64(1), uint64(2)},
		"observationTimeMilliseconds":      {eTime.UTC(), eTime.UTC().Add(time.Millisecond)},
		"postNAPTDestinationTransportPort": {uint64(22652), uint64(11385), uint64(21425), uint64(443), uint64(51413), uint64(6881), uint64(6882), uint64(80)},
		"postNAPTSourceTransportPort":      {uint64(23644), uint64(15042), uint64(23139), uint64(23241), uint64(27025), uint64(30896), uint64(31688), uint64(39328), uint64(46708), uint64(46709), uint64(46710), uint64(53966), uint64(57184), uint64(6880)},
		"postNATDestinationIPv4Address":    {net.ParseIP("188.43.111.160"), net.ParseIP("173.194.32.129"), net.ParseIP("178.47.122.160"), net.ParseIP("180.4.16.121"), net.ParseIP("185.12.241.155"), net.ParseIP("2.133.122.134"), net.ParseIP("217.118.95.65"), net.ParseIP("66.220.152.19"), net.ParseIP("86.59.237.39"), net.ParseIP("87.240.135.210"), net.ParseIP("87.240.162.79"), net.ParseIP("87.245.196.106"), net.ParseIP("91.218.122.148"), net.ParseIP("95.152.6.67")},
		"postNATSourceIPv4Address":         {net.ParseIP("185.6.25.80"), net.ParseIP("185.6.25.149"), net.ParseIP("185.6.25.154"), net.ParseIP("185.6.25.156"), net.ParseIP("185.6.25.161"), net.ParseIP("185.6.25.185"), net.ParseIP("185.6.25.197"), net.ParseIP("185.6.25.198"), net.ParseIP("185.6.25.217"), net.ParseIP("185.6.25.244"), net.ParseIP("185.6.25.49"), net.ParseIP("185.6.25.82")},
		"protocolIdentifier":               {uint64(6), uint64(17)},
		"sourceIPv4Address":                {net.ParseIP("100.64.80.149"), net.ParseIP("100.64.156.147"), net.ParseIP("100.64.149.2"), net.ParseIP("100.64.154.103"), net.ParseIP("100.64.161.25"), net.ParseIP("100.64.185.38"), net.ParseIP("100.64.197.201"), net.ParseIP("100.64.198.44"), net.ParseIP("100.64.217.104"), net.ParseIP("100.64.244.59"), net.ParseIP("100.64.49.148"), net.ParseIP("100.64.82.178")},
		"sourceTransportPort":              {uint64(64507), uint64(54592), uint64(1049), uint64(1091), uint64(20904), uint64(38804), uint64(41053), uint64(45718), uint64(52962), uint64(52963), uint64(52964), uint64(53099), uint64(54259), uint64(64569)},
	}
	scast := func(value interface{}) interface{} {
		if ip, ok := value.(net.IP); ok {
			return ip.String()
		}
		return value
	}
	for _, flow := range flows {
		for k, vlist := range expected {
			fv, exists := flow.Fields[k]
			if assert.True(t, exists, k) {
				found := false
				for _, v := range vlist {
					if found = scast(fv) == scast(v); found {
						break
					}
				}
				assert.True(t, found, k, fv)
			}
		}
	}

	v9proto, ok := proto.(*NetflowV9Protocol)
	assert.True(t, ok)

	assert.Len(t, v9proto.session.sessions, 1)
	key := MakeSessionKey(addr, 200)
	s, found := v9proto.session.sessions[key]
	assert.True(t, found)
	assert.Len(t, s.Templates, 4)
}

func mkPacket(data []uint16) []byte {
	r := make([]byte, len(data)*2)
	for idx, val := range data {
		binary.BigEndian.PutUint16(r[idx*2:(idx+1)*2], val)
	}
	return r
}

func TestOptionTemplates(t *testing.T) {
	logp.TestingSetup()
	addr := makeAddr(t, "127.0.0.1:12345")
	key := MakeSessionKey(addr, 1234)

	t.Run("Single options template", func(t *testing.T) {
		proto := New()
		flows := proto.OnPacket(mkPacket([]uint16{
			// Header
			// Version, Count, Uptime, Ts, SeqNo, Source
			9, 1, 11, 11, 22, 22, 33, 33, 0, 1234,
			// Set #1 (options template)
			1, 24, /*len of set*/
			999, 4 /*scope len*/, 10, /*opts len*/
			1, 4, // Fields
			2, 4,
			3, 4,
			0, // Padding
		}), addr)
		assert.Empty(t, flows)

		v9proto, ok := proto.(*NetflowV9Protocol)
		assert.True(t, ok)

		assert.Len(t, v9proto.session.sessions, 1)
		s, found := v9proto.session.sessions[key]
		assert.True(t, found)
		assert.Len(t, s.Templates, 1)
		otp := s.GetTemplate(999)
		assert.NotNil(t, otp)
		_, ok = otp.(OptionsTemplate)
		assert.True(t, ok)
	})

	t.Run("Multiple options template", func(t *testing.T) {
		proto := New()
		raw := mkPacket([]uint16{
			// Header
			// Version, Count, Uptime, Ts, SeqNo, Source
			9, 1, 11, 11, 22, 22, 33, 33, 0, 1234,
			// Set #1 (options template)
			1, 22 + 26, /*len of set*/
			999, 4 /*scope len*/, 8, /*opts len*/
			1, 4, // Fields
			2, 4,
			3, 4,
			998, 8, 12,
			1, 1,
			2, 2,
			3, 3,
			4, 4,
			5, 5,
			0,
		})
		flows := proto.OnPacket(raw, addr)
		assert.Empty(t, flows)

		v9proto, ok := proto.(*NetflowV9Protocol)
		assert.True(t, ok)
		assert.Len(t, v9proto.session.sessions, 1)
		s, found := v9proto.session.sessions[key]
		assert.True(t, found)
		assert.Len(t, s.Templates, 2)
		for _, id := range []uint16{998, 999} {
			otp := s.GetTemplate(id)
			assert.NotNil(t, otp)
			_, ok = otp.(OptionsTemplate)
			assert.True(t, ok)
		}
	})

	t.Run("records discarded", func(t *testing.T) {
		proto := New()
		raw := mkPacket([]uint16{
			// Header
			// Version, Count, Uptime, Ts, SeqNo, Source
			9, 1, 11, 11, 22, 22, 33, 33, 0, 1234,
			// Set #1 (options template)
			9998, 8, /*len of set*/
			1, 2,
		})
		flows := proto.OnPacket(raw, addr)
		assert.Empty(t, flows)

		v9proto, ok := proto.(*NetflowV9Protocol)
		assert.True(t, ok)

		assert.Len(t, v9proto.session.sessions, 1)
		s, found := v9proto.session.sessions[key]
		assert.True(t, found)
		assert.Len(t, s.Templates, 0)

		raw = mkPacket([]uint16{
			// Header
			// Version, Count, Uptime, Ts, SeqNo, Source
			9, 1, 11, 11, 22, 22, 33, 33, 0, 1234,
			// Set #1 (options template)
			1, 10, /*len of set*/
			9998, 0, 0,
		})
		flows = proto.OnPacket(raw, addr)
		assert.Empty(t, flows)
		assert.Len(t, v9proto.session.sessions, 1)
		assert.Len(t, s.Templates, 1)
	})
}
