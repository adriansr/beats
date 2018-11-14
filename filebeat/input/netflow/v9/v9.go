// TODO: License

package v9

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/inputsource"
	"github.com/elastic/beats/libbeat/common/atomic"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	ProtocolName                = "v9"
	NetflowV9ProtocolID  uint16 = 9
	TemplateFlowSetID           = 0
	TemplateOptionsSetID        = 1
)

var (
	ErrNoData = errors.New("not enough data")

	id atomic.Int
)

type NetflowV9Protocol struct {
	id      int
	logger  *logp.Logger
	session SessionMap
}

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	proto := &NetflowV9Protocol{
		id:      id.Inc(),
		session: NewSessionMap(),
	}
	proto.logger = logp.NewLogger(proto.String())
	return proto
}

func (p *NetflowV9Protocol) String() string {
	return fmt.Sprintf("netflowv9-%d", p.id)
}

func (_ NetflowV9Protocol) ID() uint16 {
	return NetflowV9ProtocolID
}

func (p *NetflowV9Protocol) OnPacket(data []byte, metadata inputsource.NetworkMetadata) (flows []flow.Flow) {
	buf := bytes.NewBuffer(data)
	header, err := ReadPacketHeader(buf)
	if err != nil {
		p.logger.Errorf("Unable to read V9 header: %v", err)
		return nil
	}
	p.logger.Debugf("Received %d bytes from %s: %+v", len(data), metadata.RemoteAddr.String(), header)

	session := p.session.Lookup(MakeSessionKey(metadata.RemoteAddr, header.SourceID))

	for {
		set, err := ReadSetHeader(buf)
		if err != nil || set.IsPadding() {
			break
		}
		if buf.Len() < set.BodyLength() {
			p.logger.Warnf("set %+v overflows packet", set)
			break
		}
		body := bytes.NewBuffer(buf.Next(set.BodyLength()))
		p.logger.Debugf(" - Set %d len %d", set.SetID, set.BodyLength())

		f, err := p.parseSet(header, set.SetID, session, body)
		if err != nil {
			p.logger.Warnf("Error parsing set: %v", err)
			break
		}
		flows = append(flows, f...)
	}
	return flows
}

func (p *NetflowV9Protocol) parseSet(
	header PacketHeader,
	setId uint16,
	session *SessionState,
	buf *bytes.Buffer) ([]flow.Flow, error) {
	switch setId {
	case TemplateFlowSetID:
		var err error
		template, err := readTemplateFlowSet(buf)
		if err != nil {
			return nil, err
		}
		if pending := session.AddTemplate(template); len(pending) > 0 {
			// TODO
			p.logger.Warnf("Got %d pending records", len(pending))
		}

	case TemplateOptionsSetID:
		// TODO
	default:
		if setId < 256 {
			return nil, fmt.Errorf("set id %d not supported", setId)
		}
		// TODO: Make concurrent
		if template := session.GetTemplate(setId); template != nil {
			return template.Apply(header, buf)
		} else {
			session.StorePending(setId, buf.Bytes())
		}
	}
	return nil, nil
}

type PacketHeader struct {
	Version, Count                            uint16
	SysUptime, UnixSecs, SequenceNo, SourceID uint32
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

func ReadPacketHeader(buf *bytes.Buffer) (PacketHeader, error) {
	var data [20]byte
	n, err := buf.Read(data[:])
	if n != len(data) || err != nil {
		return PacketHeader{}, ErrNoData
	}
	return PacketHeader{
		Version:    binary.BigEndian.Uint16(data[:2]),
		Count:      binary.BigEndian.Uint16(data[2:4]),
		SysUptime:  binary.BigEndian.Uint32(data[4:8]),
		UnixSecs:   binary.BigEndian.Uint32(data[8:12]),
		SequenceNo: binary.BigEndian.Uint32(data[12:16]),
		SourceID:   binary.BigEndian.Uint32(data[16:20]),
	}, nil
}

func ReadSetHeader(buf *bytes.Buffer) (SetHeader, error) {
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
