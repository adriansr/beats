// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

// TODO: License

package v9

import (
	"bytes"
	"errors"
	"net"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	ProtocolName                 = "v9"
	LogSelector                  = "netflow-v9"
	ProtocolID            uint16 = 9
	MaxSequenceDifference        = 100
)

var (
	ErrNoData = errors.New("not enough data")
)

type NetflowV9Protocol struct {
	decoder Decoder
	logger  *logp.Logger
	Session SessionMap
	done    chan struct{}
}

var _ registry.Protocol = (*NetflowV9Protocol)(nil)

func init() {
	registry.ProtocolRegistry.Register(ProtocolName, New)
}

func New() registry.Protocol {
	return NewProtocolWithDecoder(DecoderV9{}, logp.NewLogger(LogSelector))
}

func NewProtocolWithDecoder(decoder Decoder, logger *logp.Logger) *NetflowV9Protocol {
	return &NetflowV9Protocol{
		decoder: decoder,
		Session: NewSessionMap(),
		logger:  logger,
	}
}

func (_ NetflowV9Protocol) ID() uint16 {
	return ProtocolID
}

func (p *NetflowV9Protocol) Start() error {
	p.done = make(chan struct{})
	go p.Session.CleanupLoop(time.Millisecond*5000, p.done, p.logger)
	return nil
}

func (p *NetflowV9Protocol) Stop() error {
	close(p.done)
	return nil
}

func (p *NetflowV9Protocol) OnPacket(data []byte, source net.Addr) (flows []record.Record) {
	buf := bytes.NewBuffer(data)
	header, err := p.decoder.ReadPacketHeader(buf)
	if err != nil {
		p.logger.Errorf("Unable to read V9 header: %v", err)
		return nil
	}
	p.logger.Debugf("Received %d bytes from %s: %+v", len(data), source, header)

	session := p.Session.GetOrCreate(MakeSessionKey(source))
	remote := source.String()

	if header.SequenceNo < session.lastSequence && header.SequenceNo-session.lastSequence > MaxSequenceDifference {
		session.Reset()
		p.logger.Warnf("Session %s reset (sequence=%d last=%d)", remote, header.SequenceNo, session.lastSequence)
	}
	session.lastSequence = header.SequenceNo

	for {
		set, err := p.decoder.ReadSetHeader(buf)
		if err != nil || set.IsPadding() {
			break
		}
		if buf.Len() < set.BodyLength() {
			p.logger.Warnf("set %+v overflows packet from %s", set, source)
			break
		}
		body := bytes.NewBuffer(buf.Next(set.BodyLength()))
		p.logger.Debugf(" - Set %d len %d", set.SetID, set.BodyLength())

		f, err := p.parseSet(set.SetID, session, header.SourceID, body)
		if err != nil {
			p.logger.Warnf("Error parsing set %d: %v", set.SetID, err)
			break
		}
		flows = append(flows, f...)
	}
	metadata := header.ExporterMetadata(source)
	for idx := range flows {
		flows[idx].Exporter = metadata
		flows[idx].Timestamp = header.UnixSecs
	}
	return flows
}

func (p *NetflowV9Protocol) parseSet(
	setID uint16,
	session *SessionState,
	sourceID uint32,
	buf *bytes.Buffer) (flows []record.Record, err error) {

	if setID >= 256 {
		// Flow of Options record, lookup template and generate flows
		if template := session.GetTemplate(sourceID, setID); template != nil {
			return template.Apply(buf, 0)
		}
		return nil, nil
	}

	// Template sets
	templates, err := p.decoder.ReadTemplateSet(setID, buf)
	if err != nil {
		return nil, err
	}
	for _, template := range templates {
		session.AddTemplate(sourceID, template)
	}
	return flows, nil
}
