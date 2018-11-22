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
	"errors"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

var ErrNoData = errors.New("not enough data")

type Template interface {
	TemplateID() uint16
	Apply(data *bytes.Buffer, num int) ([]record.Record, error)
}

type FieldTemplate struct {
	Length uint16
	Info   *fields.Field
}

func PopulateFieldMap(dest common.MapStr, fields []FieldTemplate, buf []byte, pos int) (int, error) {
	limit := len(buf)
	for _, field := range fields {
		if pos >= limit {
			return 0, errors.New("template fields overflow record")
		}
		if fieldInfo := field.Info; fieldInfo != nil {
			value, err := fieldInfo.Decoder.Decode(buf[pos : pos+int(field.Length)])
			if err != nil {
				logp.Warn("Unable to decode field '%s' in template", fieldInfo.Name)
			}
			if len(fieldInfo.Name) > 0 {
				dest[fieldInfo.Name] = value
			}
		}
		pos += int(field.Length)
	}
	return pos, nil
}
