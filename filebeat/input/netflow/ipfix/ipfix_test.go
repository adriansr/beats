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

package ipfix

import (
	"encoding/hex"
	"testing"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/filebeat/input/netflow/test"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/stretchr/testify/assert"
)

func TestMessageWithOptions(t *testing.T) {
	rawString := "" +
		"000a01e45bf435e1000000a500000000000200480400001000080004000c0004" +
		"0001000400020004000a0004000e000400070002000b00020004000100060001" +
		"003c00010005000100200002003a000200160004001500040002004808000010" +
		"001b0010001c00100001000400020004000a0004000e000400070002000b0002" +
		"0004000100060001003c000100050001008b0002003a00020016000400150004" +
		"0003001e010000050001008f000400a000080130000201310002013200040100" +
		"00180000e9160000016731f277e100010001000000630400010ed83acd35d5da" +
		"354b0000002e0000000100000000000000000fb9005006100400000000006a53" +
		"cb3c6a53cb3c6f4de601d5da354b000000300000000100000000000000008022" +
		"005006180400000000006a53cb3c6a53cb3cd69bae4fd5da354b000000340000" +
		"000100000000000000007a51005006180400000000006a53cb3c6a53cb3cb9ae" +
		"3002d5da354b00000034000000010000000000000000e1e50050061804000000" +
		"00006a53cb3c6a53cb3cd83acd56d5da354b0000002e00000001000000000000" +
		"0000d317005006100400000000006a53cb3c6a53cb3cdbbb956bd5da354b0000" +
		"003c000000010000000000000000b235005006180400000000006a53cb3c6a53" +
		"cb3c0000"
	raw, err := hex.DecodeString(rawString)
	assert.NoError(t, err)

	captureTimeMillis, err := time.Parse(time.RFC3339, "2018-11-20T16:27:13.249Z")
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	captureTime := time.Unix(captureTimeMillis.Unix(), 0).UTC()
	expected := record.Record{
		Type:      record.Options,
		Timestamp: captureTime,
		Fields: common.MapStr{
			"scope": common.MapStr{
				"meteringProcessId": uint64(59670),
			},
			"options": common.MapStr{
				"samplingPacketInterval":     uint64(1),
				"samplingPacketSpace":        uint64(99),
				"selectorAlgorithm":          uint64(1),
				"systemInitTimeMilliseconds": captureTimeMillis,
			},
		},
		Exporter: common.MapStr{
			"address":   "127.0.0.1:1234",
			"sourceId":  uint64(0),
			"timestamp": captureTime,
			"uptime":    uint64(0),
			"version":   uint64(10),
		},
	}
	proto := New()
	flows := proto.OnPacket(raw, test.MakeAddress(t, "127.0.0.1:1234"))
	if assert.Len(t, flows, 7) {
		test.AssertFlowsEqual(t, expected, flows[0])
		assert.Equal(t, record.Options, flows[0].Type)
		for i := 1; i < len(flows); i++ {
			assert.Equal(t, record.Flow, flows[i].Type)
		}
	}
}

func TestOptionTemplates(t *testing.T) {
	logp.TestingSetup()
	addr := test.MakeAddress(t, "127.0.0.1:12345")
	key := v9.MakeSessionKey(addr)

	t.Run("Single options template", func(t *testing.T) {
		proto := New()
		flows := proto.OnPacket(test.MakePacket([]uint16{
			// Header
			// Version, Count, Ts, SeqNo, Source
			10, 1, 11, 11, 22, 22, 0, 1234,
			// Set #1 (options template)
			3, 24, /*len of set*/
			999, 3 /*total field count */, 1, /*scope field count*/
			1, 4, // Fields
			2, 4,
			3, 4,
			0, // Padding
		}), addr)
		assert.Empty(t, flows)

		ipfix, ok := proto.(*IPFixProtocol)
		assert.True(t, ok)
		v9proto := ipfix.NetflowV9Protocol
		assert.Len(t, v9proto.Session.Sessions, 1)
		s, found := v9proto.Session.Sessions[key]
		assert.True(t, found)
		assert.Len(t, s.Templates, 1)
		otp := s.GetTemplate(1234, 999)
		assert.NotNil(t, otp)
		_, ok = otp.(*template.OptionsTemplate)
		assert.True(t, ok)
	})

	t.Run("Multiple options template", func(t *testing.T) {
		proto := New()
		raw := test.MakePacket([]uint16{
			// Header
			// Version, Count, Ts, SeqNo, Source
			10, 2, 11, 11, 22, 22, 0, 1234,
			// Set #1 (options template)
			3, 22 + 26, /*len of set*/
			999, 3 /*total field count*/, 2, /*scope field count*/
			1, 4, // Fields
			2, 4,
			3, 4,
			998, 5, 3,
			1, 4,
			2, 2,
			3, 3,
			4, 1,
			5, 1,
			0,
		})
		flows := proto.OnPacket(raw, addr)
		assert.Empty(t, flows)

		ipfix, ok := proto.(*IPFixProtocol)
		v9proto := ipfix.NetflowV9Protocol
		assert.True(t, ok)
		assert.Len(t, v9proto.Session.Sessions, 1)
		s, found := v9proto.Session.Sessions[key]
		assert.True(t, found)
		assert.Len(t, s.Templates, 2)
		for _, id := range []uint16{998, 999} {
			otp := s.GetTemplate(1234, id)
			assert.NotNil(t, otp)
			_, ok = otp.(*template.OptionsTemplate)
			assert.True(t, ok)
		}
	})

	t.Run("records discarded", func(t *testing.T) {
		proto := New()
		raw := test.MakePacket([]uint16{
			// Header
			// Version, Count, Ts, SeqNo, Source
			10, 1, 11, 11, 22, 22, 0, 1234,
			// Set #1 (options template)
			9998, 8, /*len of set*/
			1, 2,
		})
		flows := proto.OnPacket(raw, addr)
		assert.Empty(t, flows)

		ipfix, ok := proto.(*IPFixProtocol)
		assert.True(t, ok)
		v9proto := ipfix.NetflowV9Protocol

		assert.Len(t, v9proto.Session.Sessions, 1)
		s, found := v9proto.Session.Sessions[key]
		assert.True(t, found)
		assert.Len(t, s.Templates, 0)

		raw = test.MakePacket([]uint16{
			// Header
			// Version, Count, Ts, SeqNo, Source
			10, 1, 11, 11, 22, 22, 0, 1234,
			// Set #1 (options template)
			3, 10, /*len of set*/
			9998, 0, 0,
		})
		flows = proto.OnPacket(raw, addr)
		assert.Empty(t, flows)
		assert.Len(t, v9proto.Session.Sessions, 1)
		assert.Len(t, s.Templates, 1)
	})
}
