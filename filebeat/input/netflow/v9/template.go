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

type OptionsTemplate struct {
	ID      uint16
	Created time.Time
}

func (t *OptionsTemplate) TemplateID() uint16 {
	return t.ID
}

func (t *OptionsTemplate) CreationDate() time.Time {
	return t.Created
}

func (t *OptionsTemplate) Apply(header PacketHeader, data *bytes.Buffer) ([]flow.Flow, error) {
	// Option parsing unimplemented
	return nil, nil
}

func readTemplateFlowSet(buf *bytes.Buffer) (templates []Template, err error) {
	now := time.Now()
	var row [4]byte
	for {
		if buf.Len() < 4 {
			return templates, nil
		}
		if n, err := buf.Read(row[:]); err != nil || n != len(row) {
			return nil, ErrNoData
		}
		template := &RecordTemplate{
			ID:      binary.BigEndian.Uint16(row[:2]),
			Created: now,
		}
		if template.ID < 256 {
			return nil, errors.New("invalid template id")
		}
		count := int(binary.BigEndian.Uint16(row[2:]))
		// TODO: Extra IPFIX data (Enterprise)
		if buf.Len() < 2*count {
			return nil, ErrNoData
		}
		template.Fields = make([]FieldTemplate, count)
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
			template.TotalLength += int(field.Length)
			if fieldInfo, found := fields.IpfixFields[key]; found {
				min, max := fieldInfo.Decoder.MinLength(), fieldInfo.Decoder.MaxLength()
				if min <= field.Length && field.Length <= max {
					field.Info = fieldInfo
				} else {
					logp.Warn("Size of field %s in template %d is out of bounds (size=%d, min=%d, max=%d)", fieldInfo.Name, template.ID, field.Length, min, max)
				}
			} else {
				logp.Warn("Field %v in template %d not found", key, template.ID)
			}
			template.Fields[i] = field
		}
		templates = append(templates, template)

	}
	return templates, nil
}

func readOptionsTemplateFlowSet(buf *bytes.Buffer) (templates []Template, err error) {
	now := time.Now()
	var header [6]byte
	for buf.Len() >= len(header) {
		if n, err := buf.Read(header[:]); err != nil || n < len(header) {
			if err == nil {
				err = ErrNoData
			}
			return nil, err
		}
		tID := binary.BigEndian.Uint16(header[:2])
		scopeLen := binary.BigEndian.Uint16(header[2:4])
		optsLen := binary.BigEndian.Uint16(header[4:])
		length := optsLen + scopeLen
		if buf.Len() < int(length) {
			return nil, ErrNoData
		}
		// Skip contents of template (ignored)
		buf.Next(int(length))
		templates = append(templates, &OptionsTemplate{
			ID:      tID,
			Created: now,
		})
	}
	return templates, nil
}
