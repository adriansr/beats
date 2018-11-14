package v9

import (
	"bytes"
	"encoding/binary"
	"errors"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/tehmaze/netflow/translate"
)

type Template interface {
	TemplateID() uint16
	CreationDate() time.Time
	Apply(header PacketHeader, data *bytes.Buffer) ([]flow.Flow, error)
}

type FieldTemplate struct {
	Type, Length uint16
}

type RecordTemplate struct {
	ID             uint16
	Fields         []FieldTemplate
	Created        time.Time
	TotalLength    int
	MaxFieldLength int
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
	ev = make(map[string]interface{})
	buf := make([]byte, t.TotalLength)
	n, err := data.Read(buf)
	if err != nil || n < int(t.TotalLength) {
		return ev, ErrNoData
	}
	pos := 0
	for _, field := range t.Fields {
		key := translate.Key{
			EnterpriseID: 0,
			FieldID:      field.Type,
		}
		fieldInfo, err := translate.TranslatorForField(key)
		if err != nil {
			return ev, err
		}
		value := translate.Bytes(buf[pos:pos+int(field.Length)], fieldInfo.Type)
		ev[fieldInfo.Name] = value
		pos += int(field.Length)
		//raw.Put(fieldInfo.Name, fmt.Sprintf("%s:%d:%+v", hex.EncodeToString(buf[:n]), n, fieldInfo.Type))
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
		t.Fields[i].Type = binary.BigEndian.Uint16(row[:2])
		length := binary.BigEndian.Uint16(row[2:])
		t.Fields[i].Length = length
		t.TotalLength += int(length)
		if int(length) > t.MaxFieldLength {
			t.MaxFieldLength = int(length)
		}
	}
	t.Created = time.Now()
	// TODO: Check fields
	return t, nil
}
