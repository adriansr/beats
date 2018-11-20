package v9

import (
	"bytes"
	"errors"
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
		Fields: common.MapStr{
			"type": "flow",
		},
	}
	if _, err = PopulateFieldMap(ev.Fields, t.Fields, buf, 0); err != nil {
		return ev, err
	}
	return ev, nil
}

type OptionsTemplate struct {
	ID          uint16
	Scope       []FieldTemplate
	Options     []FieldTemplate
	TotalLength int
}

func (t *OptionsTemplate) TemplateID() uint16 {
	return t.ID
}

func (t *OptionsTemplate) Apply(data *bytes.Buffer) ([]flow.Flow, error) {
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

func PopulateFieldMap(dest common.MapStr, fields []FieldTemplate, buf []byte, pos int) (int, error) {
	var err error
	limit := len(buf)
	for _, field := range fields {
		if pos >= limit {
			return 0, errors.New("template fields overflow record")
		}
		if fieldInfo := field.Info; fieldInfo != nil {
			if dest[fieldInfo.Name], err = fieldInfo.Decoder.Decode(buf[pos : pos+int(field.Length)]); err != nil {
				logp.Warn("Unable to decode field '%s' in template", fieldInfo.Name)
			}
		}
		pos += int(field.Length)
	}
	return pos, nil
}

func (t *OptionsTemplate) ApplyOne(data *bytes.Buffer) (ev flow.Flow, err error) {
	if data.Len() != t.TotalLength {
		return ev, ErrNoData
	}
	buf := make([]byte, t.TotalLength)
	n, err := data.Read(buf)
	if err != nil || n < int(t.TotalLength) {
		return ev, ErrNoData
	}
	scope := common.MapStr{}
	options := common.MapStr{}
	ev = flow.Flow{
		// TODO: Time of reception for stored flow records
		Timestamp: time.Now(),
		Fields: common.MapStr{
			"type":    "options",
			"scope":   scope,
			"options": options,
		},
	}
	pos, err := PopulateFieldMap(scope, t.Scope, buf, 0)
	if err != nil {
		return ev, err
	}
	pos, err = PopulateFieldMap(options, t.Options, buf, pos)
	if err != nil {
		return ev, err
	}
	return ev, nil
}
