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

func ValidateTemplate(t testing.TB, template *Template) bool {
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
	return assert.Equal(t, template.TotalLength, sum) &&
		assert.Equal(t, 0, template.ScopeFields)
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

func AssertTemplateEquals(t testing.TB, expected *Template, actual *Template) bool {
	if expected == nil && actual == nil {
		return true
	}
	if !assert.True(t, (expected == nil) == (actual == nil)) {
		return false
	}
	assert.Equal(t, expected.VariableLength, actual.VariableLength)
	assert.Equal(t, expected.TotalLength, actual.TotalLength)
	assert.Equal(t, expected.ScopeFields, actual.ScopeFields)
	assert.Equal(t, actual.ID, actual.ID)
	return AssertFieldsEquals(t, actual.Fields, actual.Fields)
}
