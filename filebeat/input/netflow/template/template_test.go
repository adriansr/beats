package template

import (
	"bytes"
	"net"
	"testing"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/filebeat/input/netflow/test"
	"github.com/elastic/beats/libbeat/common"
	"github.com/stretchr/testify/assert"
)

func TestTemplate_Apply(t *testing.T) {
	longField := make([]byte, 0x0456)
	for i := range longField {
		longField[i] = byte(i)
	}
	for _, tc := range []struct {
		title    string
		record   Template
		data     []byte
		count    int
		expected []record.Record
		err      error
	}{
		{
			title: "empty template",
			record: Template{
				TotalLength: 0,
			},
		},
		{
			title: "single record guess length and pad",
			record: Template{
				TotalLength: 7,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3, 0x12, 0x34, 59, 0,
			},
			count: 0,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("10.1.2.3"),
						"destinationTransportPort": uint64(0x1234),
						"ipClassOfService":         uint64(59),
					},
				},
			},
		},
		{
			title: "two records guess length",
			record: Template{
				TotalLength: 7,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3, 0x12, 0x34, 59,
				127, 0, 0, 1, 0, 80, 12,
			},
			count: 0,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("10.1.2.3"),
						"destinationTransportPort": uint64(0x1234),
						"ipClassOfService":         uint64(59),
					},
				},
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("127.0.0.1"),
						"destinationTransportPort": uint64(80),
						"ipClassOfService":         uint64(12),
					},
				},
			},
		},
		{
			title: "single record with count",
			record: Template{
				TotalLength: 7,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3, 0x12, 0x34, 59, 0,
			},
			count: 1,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("10.1.2.3"),
						"destinationTransportPort": uint64(0x1234),
						"ipClassOfService":         uint64(59),
					},
				},
			},
		},
		{
			title: "single record with count excess",
			record: Template{
				TotalLength: 7,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3, 0x12, 0x34, 59,
				127, 0, 0, 1, 0, 80, 12,
			},
			count: 1,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("10.1.2.3"),
						"destinationTransportPort": uint64(0x1234),
						"ipClassOfService":         uint64(59),
					},
				},
			},
		},
		{
			title: "two records with count",
			record: Template{
				TotalLength: 7,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: 2, Info: &fields.Field{Name: "destinationTransportPort", Decoder: fields.Unsigned16}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3, 0x12, 0x34, 59,
				127, 0, 0, 1, 0, 80, 12,
			},
			count: 2,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("10.1.2.3"),
						"destinationTransportPort": uint64(0x1234),
						"ipClassOfService":         uint64(59),
					},
				},
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address":        net.ParseIP("127.0.0.1"),
						"destinationTransportPort": uint64(80),
						"ipClassOfService":         uint64(12),
					},
				},
			},
		},
		{
			title: "single record variable length guess count",
			record: Template{
				TotalLength:    6,
				VariableLength: true,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: VariableLength, Info: &fields.Field{Name: "vpnIdentifier", Decoder: fields.OctetArray}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3,
				5, 1, 2, 3, 4, 5,
				93,
			},
			count: 0,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address": net.ParseIP("10.1.2.3"),
						"vpnIdentifier":     []byte{1, 2, 3, 4, 5},
						"ipClassOfService":  uint64(93),
					},
				},
			},
		},
		{
			title: "multiple record variable length guess count",
			record: Template{
				TotalLength:    6,
				VariableLength: true,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: VariableLength, Info: &fields.Field{Name: "vpnIdentifier", Decoder: fields.OctetArray}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: []byte{
				10, 1, 2, 3,
				5, 1, 2, 3, 4, 5,
				93,
				10, 1, 2, 3,
				2, 123, 234,
				93,
			},
			count: 0,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address": net.ParseIP("10.1.2.3"),
						"vpnIdentifier":     []byte{1, 2, 3, 4, 5},
						"ipClassOfService":  uint64(93),
					},
				},
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address": net.ParseIP("10.1.2.3"),
						"vpnIdentifier":     []byte{123, 234},
						"ipClassOfService":  uint64(93),
					},
				},
			},
		},
		{
			title: "long variable length",
			record: Template{
				TotalLength:    6,
				VariableLength: true,
				Fields: []FieldTemplate{
					{Length: 4, Info: &fields.Field{Name: "sourceIPv4Address", Decoder: fields.Ipv4Address}},
					{Length: VariableLength, Info: &fields.Field{Name: "vpnIdentifier", Decoder: fields.OctetArray}},
					{Length: 1, Info: &fields.Field{Name: "ipClassOfService", Decoder: fields.Unsigned8}},
				},
			},
			data: append([]byte{10, 1, 2, 3, 0xFF, 0x04, 0x56},
				append(append([]byte{}, longField...), 93, 10, 1, 2, 3, 2, 123, 234, 93)...),
			count: 2,
			expected: []record.Record{
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address": net.ParseIP("10.1.2.3"),
						"vpnIdentifier":     longField,
						"ipClassOfService":  uint64(93),
					},
				},
				{
					Type: record.Flow,
					Fields: common.MapStr{
						"sourceIPv4Address": net.ParseIP("10.1.2.3"),
						"vpnIdentifier":     []byte{123, 234},
						"ipClassOfService":  uint64(93),
					},
				},
			},
		},
	} {
		t.Run(tc.title, func(t *testing.T) {
			actual, err := tc.record.Apply(bytes.NewBuffer(tc.data), tc.count)
			assert.Equal(t, tc.err, err)
			if assert.Len(t, actual, len(tc.expected)) {
				for i, record := range actual {
					test.AssertRecordsEqual(t, tc.expected[i], record)
				}
			}
		})
	}
}

func TestOptionsTemplate_Apply(t *testing.T) {
	for _, tc := range []struct {
		title    string
		record   Template
		data     []byte
		count    int
		expected []record.Record
		err      error
	}{} {
		t.Run(tc.title, func(t *testing.T) {
			actual, err := tc.record.Apply(bytes.NewBuffer(tc.data), tc.count)
			assert.Equal(t, tc.err, err)
			if assert.Len(t, actual, len(tc.expected)) {
				for i, record := range actual {
					test.AssertRecordsEqual(t, tc.expected[i], record)
				}
			}
		})
	}
}
