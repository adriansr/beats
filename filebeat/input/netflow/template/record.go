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
	"math"

	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/libbeat/common"
)

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
