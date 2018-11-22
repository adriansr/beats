package v9

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	TemplateFlowSetID    = 0
	TemplateOptionsSetID = 1
)

type Decoder interface {
	ReadPacketHeader(*bytes.Buffer) (PacketHeader, error)
	ReadSetHeader(*bytes.Buffer) (SetHeader, error)
	ReadTemplateSet(setID uint16, buf *bytes.Buffer) ([]template.Template, error)
	ReadFieldDefinition(*bytes.Buffer) (field fields.Key, length uint16, err error)
}

type DecoderV9 struct{}

var _ Decoder = (*DecoderV9)(nil)

func (_ DecoderV9) ReadPacketHeader(buf *bytes.Buffer) (PacketHeader, error) {
	var data [20]byte
	n, err := buf.Read(data[:])
	if n != len(data) || err != nil {
		return PacketHeader{}, ErrNoData
	}
	return PacketHeader{
		Version:    binary.BigEndian.Uint16(data[:2]),
		Count:      binary.BigEndian.Uint16(data[2:4]),
		SysUptime:  binary.BigEndian.Uint32(data[4:8]),
		UnixSecs:   time.Unix(int64(binary.BigEndian.Uint32(data[8:12])), 0),
		SequenceNo: binary.BigEndian.Uint32(data[12:16]),
		SourceID:   binary.BigEndian.Uint32(data[16:20]),
	}, nil
}

func (_ DecoderV9) ReadSetHeader(buf *bytes.Buffer) (SetHeader, error) {
	var data [4]byte
	n, err := buf.Read(data[:])
	if n != len(data) || err != nil {
		return SetHeader{}, ErrNoData
	}
	return SetHeader{
		SetID:  binary.BigEndian.Uint16(data[:2]),
		Length: binary.BigEndian.Uint16(data[2:4]),
	}, nil
}

func (d DecoderV9) ReadTemplateSet(setID uint16, buf *bytes.Buffer) ([]template.Template, error) {
	switch setID {
	case TemplateFlowSetID:
		return ReadTemplateFlowSet(d, buf)
	case TemplateOptionsSetID:
		return ReadOptionsTemplateFlowSet(d, buf)
	default:
		return nil, fmt.Errorf("set id %d not supported", setID)
	}
}

func (d DecoderV9) ReadFieldDefinition(buf *bytes.Buffer) (field fields.Key, length uint16, err error) {
	var row [4]byte
	if n, err := buf.Read(row[:]); err != nil || n != len(row) {
		return field, length, ErrNoData
	}
	field.FieldID = binary.BigEndian.Uint16(row[:2])
	return field, binary.BigEndian.Uint16(row[2:]), nil
}

func ReadFields(d Decoder, buf *bytes.Buffer, count int) (readFields []template.FieldTemplate, totalLength int, err error) {
	readFields = make([]template.FieldTemplate, count)
	for i := 0; i < count; i++ {
		key, length, err := d.ReadFieldDefinition(buf)
		if err != nil {
			return nil, 0, ErrNoData
		}
		field := template.FieldTemplate{
			Length: length,
		}
		totalLength += int(field.Length)
		if fieldInfo, found := fields.Fields[key]; found {
			min, max := fieldInfo.Decoder.MinLength(), fieldInfo.Decoder.MaxLength()
			if min <= field.Length && field.Length <= max {
				field.Info = fieldInfo
			} else {
				logp.Warn("Size of field %s in template is out of bounds (size=%d, min=%d, max=%d)", fieldInfo.Name, field.Length, min, max)
			}
		} else {
			logp.Warn("Field %v in template not found", key)
		}
		readFields[i] = field
	}
	return readFields, totalLength, nil
}

func ReadTemplateFlowSet(d Decoder, buf *bytes.Buffer) (templates []template.Template, err error) {
	var row [4]byte
	for {
		if buf.Len() < 4 {
			return templates, nil
		}
		if n, err := buf.Read(row[:]); err != nil || n != len(row) {
			return nil, ErrNoData
		}
		template := &template.RecordTemplate{
			ID: binary.BigEndian.Uint16(row[:2]),
		}
		if template.ID < 256 {
			return nil, errors.New("invalid template id")
		}
		count := int(binary.BigEndian.Uint16(row[2:]))
		if buf.Len() < 2*count {
			return nil, ErrNoData
		}
		template.Fields, template.TotalLength, err = ReadFields(d, buf, count)
		templates = append(templates, template)
	}
	return templates, nil
}

func ReadOptionsTemplateFlowSet(d Decoder, buf *bytes.Buffer) (templates []template.Template, err error) {
	var header [6]byte
	for buf.Len() >= len(header) {
		if n, err := buf.Read(header[:]); err != nil || n < len(header) {
			if err == nil {
				err = ErrNoData
			}
			return nil, err
		}
		tID := binary.BigEndian.Uint16(header[:2])
		scopeLen := int(binary.BigEndian.Uint16(header[2:4]))
		optsLen := int(binary.BigEndian.Uint16(header[4:]))
		length := optsLen + scopeLen
		if buf.Len() < int(length) {
			return nil, ErrNoData
		}
		if scopeLen&3 != 0 || optsLen&3 != 0 {
			return nil, fmt.Errorf("odd length for options template. scope=%d options=%d", scopeLen, optsLen)
		}
		template := &template.OptionsTemplate{
			ID: tID,
		}
		template.Scope, template.TotalLength, err = ReadFields(d, buf, scopeLen/4)
		if err != nil {
			return nil, err
		}
		var extraLen int
		template.Options, extraLen, err = ReadFields(d, buf, optsLen/4)
		template.TotalLength += extraLen
		templates = append(templates, template)
	}
	return templates, nil
}

type PacketHeader struct {
	Version, Count       uint16
	SysUptime            uint32
	UnixSecs             time.Time
	SequenceNo, SourceID uint32
}

type SetHeader struct {
	SetID, Length uint16
}

func (h SetHeader) BodyLength() int {
	if h.Length < 4 {
		return 0
	}
	return int(h.Length) - 4
}

func (h SetHeader) IsPadding() bool {
	return h.SetID == 0 && h.Length == 0
}

func (h PacketHeader) ExporterMetadata(source net.Addr) common.MapStr {
	return common.MapStr{
		"version":   uint64(h.Version),
		"timestamp": h.UnixSecs,
		"uptime":    uint64(h.SysUptime),
		"address":   source.String(),
		"sourceId":  uint64(h.SourceID),
	}
}
