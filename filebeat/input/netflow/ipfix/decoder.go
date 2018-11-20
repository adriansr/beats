package ipfix

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/elastic/beats/filebeat/input/netflow/fields"
	"github.com/elastic/beats/filebeat/input/netflow/v9"
)

const (
	TemplateFlowSetID           = 2
	TemplateOptionsSetID        = 3
	EnterpriseBit        uint16 = 0x8000
)

type DecoderIPFix struct {
	v9.DecoderV9
}

var _ v9.Decoder = (*DecoderIPFix)(nil)

func (_ DecoderIPFix) ReadPacketHeader(buf *bytes.Buffer) (v9.PacketHeader, error) {
	var data [16]byte
	n, err := buf.Read(data[:])
	if n != len(data) || err != nil {
		return v9.PacketHeader{}, v9.ErrNoData
	}
	return v9.PacketHeader{
		Version:    binary.BigEndian.Uint16(data[:2]),
		Count:      binary.BigEndian.Uint16(data[2:4]),
		UnixSecs:   binary.BigEndian.Uint32(data[4:8]),
		SequenceNo: binary.BigEndian.Uint32(data[8:12]),
		SourceID:   binary.BigEndian.Uint32(data[12:16]),
	}, nil
}

func (d DecoderIPFix) ReadTemplateSet(setID uint16, buf *bytes.Buffer) ([]v9.Template, error) {
	switch setID {
	case TemplateFlowSetID:
		return v9.ReadTemplateFlowSet(d, buf)
	case TemplateOptionsSetID:
		return d.ReadOptionsTemplateFlowSet(buf)
	default:
		return nil, fmt.Errorf("set id %d not supported", setID)
	}
}

func (d DecoderIPFix) ReadFieldDefinition(buf *bytes.Buffer) (field fields.Key, length uint16, err error) {
	var row [4]byte
	if n, err := buf.Read(row[:]); err != nil || n != len(row) {
		return field, length, v9.ErrNoData
	}
	field.FieldID = binary.BigEndian.Uint16(row[:2])
	length = binary.BigEndian.Uint16(row[2:])
	if field.FieldID&EnterpriseBit != 0 {
		field.FieldID &= ^EnterpriseBit
		if n, err := buf.Read(row[:]); err != nil || n != len(row) {
			return field, length, v9.ErrNoData
		}
		field.EnterpriseID = binary.BigEndian.Uint32(row[:])
	}
	return field, length, nil
}

func (d DecoderIPFix) ReadOptionsTemplateFlowSet(buf *bytes.Buffer) (templates []v9.Template, err error) {
	var header [6]byte
	for buf.Len() >= len(header) {
		if n, err := buf.Read(header[:]); err != nil || n < len(header) {
			if err == nil {
				err = v9.ErrNoData
			}
			return nil, err
		}
		tID := binary.BigEndian.Uint16(header[:2])
		totalCount := binary.BigEndian.Uint16(header[2:4])
		//scopeCount := binary.BigEndian.Uint16(header[4:])
		//length := optsLen + scopeLen
		//if buf.Len() < int(length) {
		//	return nil, ErrNoData
		//}
		// Skip contents of template (ignored)
		//buf.Next(int(length))
		for i := uint16(0); i < totalCount; i++ {
			if _, _, err = d.ReadFieldDefinition(buf); err != nil {
				return nil, err
			}
		}
		templates = append(templates, v9.OptionsTemplate(tID))
	}
	return templates, nil
}
