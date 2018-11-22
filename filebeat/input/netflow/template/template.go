package template

import (
	"bytes"
	"errors"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

var ErrNoData = errors.New("not enough data")

type Template interface {
	TemplateID() uint16
	Apply(data *bytes.Buffer, num int) ([]flow.Flow, error)
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
