package v8

import (
	"testing"

	"github.com/elastic/beats/filebeat/input/netflow/test"
)

func TestTemplates(t *testing.T) {
	for code, template := range templates {
		if !test.ValidateTemplate(t, template) {
			t.Fatal("Failed validating template for V8 record", code)
		}
	}
}
