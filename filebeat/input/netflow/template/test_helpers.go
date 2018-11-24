package template

import (
	"fmt"
	"sync"
	"testing"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/stretchr/testify/assert"
)

var (
	decoderByName = map[string]fields.Decoder{}
	once          sync.Once
)

func buildDecoderByNameMap() {
	for _, value := range fields.Fields {
		decoderByName[value.Name] = value.Decoder
	}
}

func ValidateTemplate(t testing.TB, template RecordTemplate) bool {
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

func AssertFieldsEquals(t testing.TB, expected []FieldTemplate, actual []FieldTemplate) (succeeded bool) {
	if succeeded = assert.Len(t, actual, len(expected)); succeeded {
		for idx := range expected {
			succeeded = assert.Equal(t, expected[idx].Length, actual[idx].Length, string(idx)) && succeeded
			succeeded = assert.Equal(t, expected[idx].Info, actual[idx].Info, string(idx)) && succeeded
		}
	}
	return
}

func AssertTemplateEquals(t testing.TB, expected Template, actual Template) bool {
	if expected == nil && actual == nil {
		return true
	}
	if !assert.True(t, (expected == nil) == (actual == nil)) {
		return false
	}
	switch v := expected.(type) {
	case *RecordTemplate:
		w, ok := actual.(*RecordTemplate)
		if !assert.True(t, ok) {
			return false
		}
		assert.Equal(t, v.VariableLength, w.VariableLength)
		assert.Equal(t, v.TotalLength, w.TotalLength)
		assert.Equal(t, v.ID, w.ID)
		return AssertFieldsEquals(t, v.Fields, w.Fields)

	case *OptionsTemplate:
		w, ok := actual.(*OptionsTemplate)
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
