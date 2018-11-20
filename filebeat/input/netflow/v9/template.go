package v9

import (
	"bytes"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

type Template interface {
	TemplateID() uint16
	Apply(data *bytes.Buffer) ([]flow.Flow, error)
}

type FieldTemplate struct {
	Length uint16
	Info   *fields.Field
}

type RecordTemplate struct {
	ID          uint16
	Fields      []FieldTemplate
	TotalLength int
}

func (t RecordTemplate) TemplateID() uint16 {
	return t.ID
}

func (t *RecordTemplate) Apply(data *bytes.Buffer) ([]flow.Flow, error) {
	if t.TotalLength == 0 {
		// TODO: Empty template
		return nil, nil
	}
	n := data.Len() / t.TotalLength
	events := make([]flow.Flow, 0, n)
	for i := 0; i < n; i++ {
		event, err := t.ApplyOne(bytes.NewBuffer(data.Next(t.TotalLength)))
		if err != nil {
			return events, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (t *RecordTemplate) ApplyOne(data *bytes.Buffer) (ev flow.Flow, err error) {
	if data.Len() != t.TotalLength {
		return ev, ErrNoData
	}
	buf := make([]byte, t.TotalLength)
	n, err := data.Read(buf)
	if err != nil || n < int(t.TotalLength) {
		return ev, ErrNoData
	}
	ev = flow.Flow{
		// TODO: Time of reception for stored flow records
		Timestamp: time.Now(),
		Fields:    common.MapStr{},
	}
	pos := 0
	for _, field := range t.Fields {
		if fieldInfo := field.Info; fieldInfo != nil {
			if ev.Fields[fieldInfo.Name], err = fieldInfo.Decoder.Decode(buf[pos : pos+int(field.Length)]); err != nil {
				logp.Warn("Unable to decode field '%s' in template %d", fieldInfo.Name, t.ID)
			}
		}
		pos += int(field.Length)
	}
	return ev, nil
}

type OptionsTemplate uint16

func (t OptionsTemplate) TemplateID() uint16 {
	return uint16(t)
}

func (t OptionsTemplate) Apply(data *bytes.Buffer) ([]flow.Flow, error) {
	// Option parsing unimplemented
	return nil, nil
}
