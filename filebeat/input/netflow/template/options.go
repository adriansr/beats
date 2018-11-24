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
	"io"

	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/libbeat/common"
)

type OptionsTemplate struct {
	ID             uint16
	Scope          []FieldTemplate
	Options        []FieldTemplate
	TotalLength    int
	VariableLength bool
}

func (t *OptionsTemplate) TemplateID() uint16 {
	return t.ID
}

func (t *OptionsTemplate) Apply(data *bytes.Buffer, n int) ([]record.Record, error) {
	if t.TotalLength == 0 {
		// TODO: Empty template
		return nil, nil
	}
	if n == 0 {
		if !t.VariableLength {
			n = data.Len() / t.TotalLength
		}
	}
	events := make([]record.Record, 0, n)
	for i := 0; i < n; i++ {
		event, err := t.ApplyOne(bytes.NewBuffer(data.Next(t.TotalLength)))
		if err != nil {
			return events, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (t *OptionsTemplate) ApplyOne(data *bytes.Buffer) (ev record.Record, err error) {
	if data.Len() != t.TotalLength {
		return ev, io.EOF
	}
	scope := common.MapStr{}
	options := common.MapStr{}
	ev = record.Record{
		Type: record.Options,
		Fields: common.MapStr{
			"scope":   scope,
			"options": options,
		},
	}
	if err = PopulateFieldMap(scope, t.Scope, t.VariableLength, data); err != nil {
		return ev, err
	}
	if err = PopulateFieldMap(options, t.Options, t.VariableLength, data); err != nil {
		return ev, err
	}
	return ev, nil
}
