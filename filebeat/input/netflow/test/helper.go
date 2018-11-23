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

package test

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/libbeat/common"
	"github.com/stretchr/testify/assert"
)

func MakeAddress(t testing.TB, ipPortPair string) net.Addr {
	ip, portS, err := net.SplitHostPort(ipPortPair)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	port, err := strconv.Atoi(portS)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	return &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}
}

func MakePacket(data []uint16) []byte {
	r := make([]byte, len(data)*2)
	for idx, val := range data {
		binary.BigEndian.PutUint16(r[idx*2:(idx+1)*2], val)
	}
	return r
}

func AssertMapEqual(t testing.TB, expected common.MapStr, actual common.MapStr) bool {
	for key, expectedValue := range expected {
		value, found := actual[key]
		if !assert.True(t, found, key) {
			return false
		}
		if !assert.Equal(t, expectedValue, value, key) {
			return false
		}
	}
	for key := range actual {
		_, found := expected[key]
		if !assert.True(t, found, key) {
			return false
		}
	}
	return true
}

func AssertFlowsEqual(t testing.TB, expected record.Record, actual record.Record) bool {
	if !assert.Equal(t, expected.Type, actual.Type) {
		return false
	}
	if !assert.Equal(t, expected.Timestamp, actual.Timestamp) {
		return false
	}
	if !AssertMapEqual(t, expected.Fields, actual.Fields) {
		return false
	}
	if !AssertMapEqual(t, expected.Exporter, actual.Exporter) {
		return false
	}
	return true
}

var (
	decoderByName = map[string]fields.Decoder{}
	once          sync.Once
)

func buildDecoderByNameMap() {
	for _, value := range fields.Fields {
		decoderByName[value.Name] = value.Decoder
	}
}

func ValidateTemplate(t testing.TB, template template.RecordTemplate) bool {
	once.Do(buildDecoderByNameMap)

	sum := 0
	seen := make(map[string]bool)
	for idx, field := range template.Fields {
		sum += int(field.Length)
		if field.Info != nil {
			msg := fmt.Sprintf("field[%d]: \"%s\"", idx, field.Info.Name)
			if !assert.NotNil(t, field.Info.Decoder, msg) ||
				!assert.True(t, field.Info.Decoder.MinLength() <= field.Length, msg) ||
				!assert.True(t, field.Info.Decoder.MaxLength() >= field.Length, msg) {
				return false
			}
			if !assert.False(t, seen[field.Info.Name], msg) {
				return false
			}
			seen[field.Info.Name] = true
			knownDecoder, found := decoderByName[field.Info.Name]
			if !assert.True(t, found, msg) ||
				!assert.Equal(t, knownDecoder, field.Info.Decoder, msg) {
				return false
			}
		}
	}
	return assert.Equal(t, template.TotalLength, sum)
}

func AssertFieldsEquals(t testing.TB, expected []template.FieldTemplate, actual []template.FieldTemplate) (succeeded bool) {
	if succeeded = assert.Len(t, actual, len(expected)); succeeded {
		for idx := range expected {
			succeeded = assert.Equal(t, expected[idx].Length, actual[idx].Length, string(idx)) && succeeded
			succeeded = assert.Equal(t, expected[idx].Info, actual[idx].Info, string(idx)) && succeeded
		}
	}
	return
}

func AssertTemplateEquals(t testing.TB, expected template.Template, actual template.Template) bool {
	if expected == nil && actual == nil {
		return true
	}
	if !assert.True(t, (expected == nil) == (actual == nil)) {
		return false
	}
	switch v := expected.(type) {
	case *template.RecordTemplate:
		w, ok := actual.(*template.RecordTemplate)
		if !assert.True(t, ok) {
			return false
		}
		assert.Equal(t, v.VariableLength, w.VariableLength)
		assert.Equal(t, v.TotalLength, w.TotalLength)
		assert.Equal(t, v.ID, w.ID)
		return AssertFieldsEquals(t, v.Fields, w.Fields)

	case *template.OptionsTemplate:
		w, ok := actual.(*template.OptionsTemplate)
		if !assert.True(t, ok) {
			return false
		}
		assert.Equal(t, v.VariableLength, w.VariableLength)
		assert.Equal(t, v.TotalLength, w.TotalLength)
		assert.Equal(t, v.ID, w.ID)
		return AssertFieldsEquals(t, v.Scope, w.Scope) &&
			AssertFieldsEquals(t, v.Options, w.Options)
	}
	return false
}
