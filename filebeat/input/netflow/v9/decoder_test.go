package v9

import (
	"bytes"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/filebeat/input/netflow/test"
	"github.com/elastic/beats/libbeat/logp"
	"github.com/stretchr/testify/assert"
)

func TestDecoderV9_ReadPacketHeader(t *testing.T) {
	captureTime, err := time.Parse(time.RFC3339, "2018-11-22T20:53:03Z")
	if !assert.NoError(t, err) {
		t.Fatal(err)
	}
	decoder := DecoderV9{}
	for _, tc := range []struct {
		title    string
		packet   []uint16
		expected PacketHeader
		err      error
	}{
		{
			title: "valid header",
			packet: []uint16{
				9, 4096, 0x1234, 0x5678, 23543, 5935, 0x1122, 0x3344, 0x5566, 0x7788,
			},
			expected: PacketHeader{
				Version:    9,
				Count:      4096,
				SysUptime:  0x12345678,
				UnixSecs:   captureTime.UTC(),
				SequenceNo: 0x11223344,
				SourceID:   0x55667788,
			},
		},
		{
			title: "short header",
			packet: []uint16{
				9, 4096, 0x1234, 0x5678, 23543, 5935, 0x1122, 0x3344, 0x5566,
			},
			err: io.EOF,
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			raw := test.MakePacket(tc.packet)
			header, err := decoder.ReadPacketHeader(bytes.NewBuffer(raw))
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.expected, header)
		})
	}
}

func TestDecoderV9_ReadFieldDefinition(t *testing.T) {
	decoder := DecoderV9{}
	for _, tc := range []struct {
		title  string
		raw    []byte
		field  fields.Key
		length uint16
		err    error
	}{
		{
			title: "valid field",
			raw: []byte{
				1, 2, 3, 4,
			},
			field:  fields.Key{FieldID: 0x0102},
			length: 0x0304,
		},
		{
			title: "short field",
			raw: []byte{
				1, 2, 3,
			},
			err: io.EOF,
		},
		{
			title: "ignore enterprise id",
			raw: []byte{
				0x80, 1, 2, 3,
			},
			field:  fields.Key{FieldID: 0x8001},
			length: 0x0203,
		},
		{
			title: "max length",
			raw: []byte{
				0x12, 0x34, 0xff, 0xff,
			},
			field:  fields.Key{FieldID: 0x1234},
			length: 0xffff,
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			field, length, err := decoder.ReadFieldDefinition(bytes.NewBuffer(tc.raw))
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.field, field)
			assert.Equal(t, tc.length, length)
		})
	}
}

func TestDecoderV9_ReadFields(t *testing.T) {
	logp.TestingSetup()
	decoder := DecoderV9{}
	for _, tc := range []struct {
		title    string
		packet   []uint16
		count    int
		expected template.RecordTemplate
		err      error
	}{
		{
			title: "valid fields",
			packet: []uint16{
				1, 4,
				5, 1,
				14, 2,
			},
			count: 3,
			expected: template.RecordTemplate{
				Fields: []template.FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
					{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
				},
				TotalLength: 7,
			},
		},
		{
			title: "length out of bounds",
			packet: []uint16{
				1, 4,
				5, 11,
				14, 2,
			},
			count: 3,
			expected: template.RecordTemplate{
				Fields: []template.FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
					{Length: 11},
					{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
				},
				TotalLength: 17,
			},
		},
		{
			title: "ignore enterprise ID",
			packet: []uint16{
				1, 4,
				5, 1,
				0x8000 | 8232, 2,
			},
			count: 3,
			expected: template.RecordTemplate{
				Fields: []template.FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
					{Length: 2},
				},
				TotalLength: 7,
			},
		},
		{
			title: "EOF",
			packet: []uint16{
				1, 4,
				5, 1,
			},
			count: 3,
			err:   io.EOF,
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			raw := test.MakePacket(tc.packet)
			record, err := decoder.ReadFields(bytes.NewBuffer(raw), tc.count)
			assert.Equal(t, tc.err, err)
			assert.Equal(t, tc.expected.TotalLength, record.TotalLength)
			assert.Equal(t, tc.expected.VariableLength, record.VariableLength)
			assert.Equal(t, tc.expected.ID, record.ID)
			template.AssertFieldsEquals(t, tc.expected.Fields, record.Fields)
		})
	}
}

func TestReadOptionsTemplateFlowSet(t *testing.T) {
	logp.TestingSetup()
	decoder := DecoderV9{}
	for _, tc := range []struct {
		title    string
		packet   []uint16
		expected []template.Template
		err      error
	}{
		{
			title: "valid fields",
			packet: []uint16{
				999, 4, 8,
				1, 4,
				5, 1,
				14, 2,
				998, 4, 0,
				16, 4,
			},
			expected: []template.Template{
				&template.OptionsTemplate{
					ID:          999,
					TotalLength: 7,
					Scope: []template.FieldTemplate{
						{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
					},
					Options: []template.FieldTemplate{
						{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
						{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
					},
				},
				&template.OptionsTemplate{
					ID:          998,
					TotalLength: 4,
					Scope: []template.FieldTemplate{
						{Length: 4, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
					},
					Options: []template.FieldTemplate{},
				},
			},
		},
		{
			title: "EOF",
			packet: []uint16{
				999, 44, 8,
				1, 4,
				5, 1,
				14, 2,
				1, 4, 0,
				16, 4,
			},
			err: io.EOF,
		},
		{
			title: "bad length",
			packet: []uint16{
				999, 4, 8,
				1, 4,
				5, 1,
				14, 2,
				1111, 4, 7,
				16, 4,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			err: errors.New("odd length for options template. scope=4 options=7"),
		},
		{
			title: "invalid template ID",
			packet: []uint16{
				999, 4, 8,
				1, 4,
				5, 1,
				14, 2,
				1, 4, 6,
				16, 4,
				0, 0, 0, 0, 0, 0, 0, 0,
			},
			err: errors.New("invalid template id"),
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			raw := test.MakePacket(tc.packet)
			templates, err := decoder.ReadOptionsTemplateFlowSet(bytes.NewBuffer(raw))
			assert.Equal(t, tc.err, err)
			if assert.Len(t, templates, len(tc.expected)) {
				for idx := range tc.expected {
					template.AssertTemplateEquals(t, tc.expected[idx], templates[idx])
				}
			}
		})
	}
}

func TestReadTemplateFlowSet(t *testing.T) {
	logp.TestingSetup()
	decoder := DecoderV9{}
	for _, tc := range []struct {
		title    string
		packet   []uint16
		expected []template.Template
		err      error
	}{
		{
			title: "valid fields",
			packet: []uint16{
				999, 3,
				1, 4,
				5, 1,
				14, 2,
				998, 1,
				16, 4,
			},
			expected: []template.Template{
				&template.RecordTemplate{
					ID:          999,
					TotalLength: 7,
					Fields: []template.FieldTemplate{
						{Length: 4, Info: &fields.Field{Name: "octetDeltaCount", Decoder: fields.Unsigned64}},
						{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
						{Length: 2, Info: &fields.Field{Name: "egressInterface", Decoder: fields.Unsigned32}},
					},
				},
				&template.RecordTemplate{
					ID:          998,
					TotalLength: 4,
					Fields: []template.FieldTemplate{
						{Length: 4, Info: &fields.Field{Name: "bgpSourceAsNumber", Decoder: fields.Unsigned32}},
					},
				},
			},
		},
		{
			title: "EOF",
			packet: []uint16{
				999, 44,
				1, 4,
				5, 1,
				14, 2,
				1, 4,
				16, 4,
			},
			err: io.EOF,
		},
		{
			title: "bad ID",
			packet: []uint16{
				99, 6,
				1, 4,
				5, 1,
				14, 2,
			},
			err: errors.New("invalid template id"),
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			raw := test.MakePacket(tc.packet)
			templates, err := ReadTemplateFlowSet(decoder, bytes.NewBuffer(raw))
			assert.Equal(t, tc.err, err)
			if assert.Len(t, templates, len(tc.expected)) {
				for idx := range tc.expected {
					template.AssertTemplateEquals(t, tc.expected[idx], templates[idx])
				}
			}
		})
	}
}
