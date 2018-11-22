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
	"bytes"
	"encoding/binary"
	"fmt"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
)

const (
	TemplateFlowSetID           = 2
	TemplateOptionsSetID        = 3
	EnterpriseBit        uint16 = 0x8000
)

type DecoderIPFix struct {
	v9.DecoderV9
}

var _ v9.Decoder = (*DecoderIPFix)(nil)

func (_ DecoderIPFix) ReadPacketHeader(buf *bytes.Buffer) (v9.PacketHeader, error) {
	var data [16]byte
	n, err := buf.Read(data[:])
	if n != len(data) || err != nil {
		return v9.PacketHeader{}, v9.ErrNoData
	}
	return v9.PacketHeader{
		Version:    binary.BigEndian.Uint16(data[:2]),
		Count:      binary.BigEndian.Uint16(data[2:4]),
		UnixSecs:   time.Unix(int64(binary.BigEndian.Uint32(data[4:8])), 0).UTC(),
		SequenceNo: binary.BigEndian.Uint32(data[8:12]),
		SourceID:   binary.BigEndian.Uint32(data[12:16]),
	}, nil
}

func (d DecoderIPFix) ReadTemplateSet(setID uint16, buf *bytes.Buffer) ([]template.Template, error) {
	switch setID {
	case TemplateFlowSetID:
		return v9.ReadTemplateFlowSet(d, buf)
	case TemplateOptionsSetID:
		return d.ReadOptionsTemplateFlowSet(buf)
	default:
		return nil, fmt.Errorf("set id %d not supported", setID)
	}
}

func (d DecoderIPFix) ReadFieldDefinition(buf *bytes.Buffer) (field fields.Key, length uint16, err error) {
	var row [4]byte
	if n, err := buf.Read(row[:]); err != nil || n != len(row) {
		return field, length, v9.ErrNoData
	}
	field.FieldID = binary.BigEndian.Uint16(row[:2])
	length = binary.BigEndian.Uint16(row[2:])
	if field.FieldID&EnterpriseBit != 0 {
		field.FieldID &= ^EnterpriseBit
		if n, err := buf.Read(row[:]); err != nil || n != len(row) {
			return field, length, v9.ErrNoData
		}
		field.EnterpriseID = binary.BigEndian.Uint32(row[:])
	}
	return field, length, nil
}

func (d DecoderIPFix) ReadOptionsTemplateFlowSet(buf *bytes.Buffer) (templates []template.Template, err error) {
	var header [6]byte
	for buf.Len() >= len(header) {
		if n, err := buf.Read(header[:]); err != nil || n < len(header) {
			if err == nil {
				err = v9.ErrNoData
			}
			return nil, err
		}
		template := &template.OptionsTemplate{
			ID: binary.BigEndian.Uint16(header[:2]),
		}
		totalCount := int(binary.BigEndian.Uint16(header[2:4]))
		scopeCount := int(binary.BigEndian.Uint16(header[4:]))
		if scopeCount > totalCount {
			return nil, fmt.Errorf("wrong counts in options template flowset: scope=%d total=%d", scopeCount, totalCount)
		}
		template.Scope, template.TotalLength, err = v9.ReadFields(d, buf, scopeCount)
		if err != nil {
			return nil, err
		}
		var extraLen int
		template.Options, extraLen, err = v9.ReadFields(d, buf, totalCount-scopeCount)
		template.TotalLength += extraLen
		templates = append(templates, template)
	}
	return templates, nil
}
