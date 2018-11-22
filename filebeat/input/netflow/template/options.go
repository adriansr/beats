package template

import (
	"bytes"

	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/libbeat/common"
)

type OptionsTemplate struct {
	ID          uint16
	Scope       []FieldTemplate
	Options     []FieldTemplate
	TotalLength int
}

func (t *OptionsTemplate) TemplateID() uint16 {
	return t.ID
}

func (t *OptionsTemplate) Apply(data *bytes.Buffer, n int) ([]flow.Flow, error) {
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
		//Timestamp: time.Now(),
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
