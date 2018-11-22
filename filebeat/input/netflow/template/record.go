package template

import (
	"bytes"

	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/libbeat/common"
)

type RecordTemplate struct {
	ID          uint16
	Fields      []FieldTemplate
	TotalLength int
}

func (t RecordTemplate) TemplateID() uint16 {
	return t.ID
}

func (t *RecordTemplate) Apply(data *bytes.Buffer, n int) ([]flow.Flow, error) {
	if t.TotalLength == 0 {
		// TODO: Empty template
		return nil, nil
	}
	if n == 0 {
		n = data.Len() / t.TotalLength
	}
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
		//Timestamp: time.Now(),
		Fields: common.MapStr{
			"type": "flow",
		},
	}
	if _, err = PopulateFieldMap(ev.Fields, t.Fields, buf, 0); err != nil {
		return ev, err
	}
	return ev, nil
}
