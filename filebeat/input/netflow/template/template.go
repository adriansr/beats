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

package template

import (
	"bytes"
	"encoding/binary"
	"io"
	"math"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	VariableLength uint16 = 0xffff
)

type Template struct {
	ID             uint16
	Fields         []FieldTemplate
	TotalLength    int
	VariableLength bool
	ScopeFields    int
}

type FieldTemplate struct {
	Length uint16
	Info   *fields.Field
}

func PopulateFieldMap(dest common.MapStr, fields []FieldTemplate, variableLength bool, buffer *bytes.Buffer) error {
	for _, field := range fields {
		length := field.Length
		if variableLength && length == VariableLength {
			tmp := buffer.Next(1)
			if len(tmp) != 1 {
				return io.EOF
			}
			length = uint16(tmp[0])
			if length == 255 {
				tmp = buffer.Next(2)
				if len(tmp) != 2 {
					return io.EOF
				}
				length = binary.BigEndian.Uint16(tmp)
			}
		}
		raw := buffer.Next(int(length))
		if len(raw) != int(length) {
			return io.EOF
		}
		if fieldInfo := field.Info; fieldInfo != nil {
			value, err := fieldInfo.Decoder.Decode(raw)
			if err != nil {
				logp.Warn("Unable to decode field '%s' in template", fieldInfo.Name)
				continue
			}
			dest[fieldInfo.Name] = value
		}
	}
	return nil
}

func (t *Template) Apply(data *bytes.Buffer, n int) ([]record.Record, error) {
	if t.TotalLength == 0 {
		// TODO: Empty template
		return nil, nil
	}
	if n == 0 {
		n = data.Len() / t.TotalLength
	}
	limit, alloc := n, n
	if t.VariableLength {
		limit = math.MaxInt16
		alloc = n
		if alloc > 16 {
			alloc = 16
		}
	}
	makeFn := t.makeFlow
	if t.ScopeFields > 0 {
		makeFn = t.makeOptions
	}
	events := make([]record.Record, 0, alloc)
	for i := 0; i < limit; i++ {
		event, err := makeFn(data)
		if err != nil {
			if err == io.EOF && t.VariableLength {
				break
			}
			return events, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (t *Template) makeFlow(data *bytes.Buffer) (ev record.Record, err error) {
	ev = record.Record{
		Type:   record.Flow,
		Fields: common.MapStr{},
	}
	if err = PopulateFieldMap(ev.Fields, t.Fields, t.VariableLength, data); err != nil {
		return ev, err
	}
	return ev, nil
}

func (t *Template) makeOptions(data *bytes.Buffer) (ev record.Record, err error) {
	scope := common.MapStr{}
	options := common.MapStr{}
	ev = record.Record{
		Type: record.Options,
		Fields: common.MapStr{
			"scope":   scope,
			"options": options,
		},
	}
	if err = PopulateFieldMap(scope, t.Fields[:t.ScopeFields], t.VariableLength, data); err != nil {
		return ev, err
	}
	if err = PopulateFieldMap(options, t.Fields[t.ScopeFields:], t.VariableLength, data); err != nil {
		return ev, err
	}
	return ev, nil
}
