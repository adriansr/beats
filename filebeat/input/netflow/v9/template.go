package v9

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

type Template interface {
	TemplateID() uint16
	CreationDate() time.Time
	Apply(header PacketHeader, data *bytes.Buffer) ([]flow.Flow, error)
}

type FieldTemplate struct {
	Length uint16
	Info   *fields.Field
}

type RecordTemplate struct {
	ID          uint16
	Fields      []FieldTemplate
	Created     time.Time
	TotalLength int
}

func (t RecordTemplate) TemplateID() uint16 {
	return t.ID
}

func (t RecordTemplate) CreationDate() time.Time {
	return t.Created
}

func (t *RecordTemplate) Apply(header PacketHeader, data *bytes.Buffer) ([]flow.Flow, error) {
	if t.TotalLength == 0 {
		// TODO: Empty template
		return nil, nil
	}
	n := data.Len() / t.TotalLength
	events := make([]flow.Flow, 0, n)
	for i := 0; i < n; i++ {
		event, err := t.ApplyOne(header, bytes.NewBuffer(data.Next(t.TotalLength)))
		if err != nil {
			return events, err
		}
		events = append(events, event)
	}
	return events, nil
}

func (t *RecordTemplate) ApplyOne(header PacketHeader, data *bytes.Buffer) (ev flow.Flow, err error) {
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

func readTemplateFlowSet(buf *bytes.Buffer) (t *RecordTemplate, err error) {
	var row [4]byte
	if n, err := buf.Read(row[:]); err != nil || n != len(row) {
		return nil, ErrNoData
	}
	t = new(RecordTemplate)
	if t.ID = binary.BigEndian.Uint16(row[:2]); t.ID < 256 {
		return nil, errors.New("invalid template id")
	}
	count := int(binary.BigEndian.Uint16(row[2:]))
	// TODO: Extra IPFIX data (Enterprise)
	if buf.Len() < 2*count {
		return nil, ErrNoData
	}
	t.Fields = make([]FieldTemplate, count)
	for i := 0; i < count; i++ {
		if n, err := buf.Read(row[:]); err != nil || n != len(row) {
			return nil, ErrNoData
		}
		key := fields.Key{
			EnterpriseID: 0,
			FieldID:      binary.BigEndian.Uint16(row[:2]),
		}
		field := FieldTemplate{
			Length: binary.BigEndian.Uint16(row[2:]),
		}
		t.TotalLength += int(field.Length)
		if fieldInfo, found := fields.IpfixFields[key]; found {
			min, max := fieldInfo.Decoder.MinLength(), fieldInfo.Decoder.MaxLength()
			if min <= field.Length && field.Length <= max {
				field.Info = fieldInfo
			} else {
				logp.Warn("Size of field %s in template %d is out of bounds (size=%d, min=%d, max=%d)", fieldInfo.Name, t.ID, field.Length, min, max)
			}
		} else {
			logp.Warn("Field %v in template %d not found", key, t.ID)
		}
		t.Fields[i] = field
	}
	t.Created = time.Now()
	// TODO: Check fields
	return t, nil
}
