// TODO: License

package netflow

import (
	"encoding/binary"
	"net"
	"sync"
	"time"

	"github.com/elastic/beats/filebeat/channel"
	"github.com/elastic/beats/filebeat/harvester"
	"github.com/elastic/beats/filebeat/input"
	"github.com/elastic/beats/filebeat/input/netflow/registry"
	"github.com/elastic/beats/filebeat/inputsource"
	"github.com/elastic/beats/filebeat/inputsource/udp"
	"github.com/elastic/beats/filebeat/util"
	"github.com/elastic/beats/libbeat/beat"
	"github.com/elastic/beats/libbeat/common"
	"github.com/elastic/beats/libbeat/common/atomic"
	"github.com/elastic/beats/libbeat/logp"
)

const (
	InputName = "netflow"
)

var (
	logger  *logp.Logger
	N       = 16
	Packets = atomic.NewInt(0)
	Flows   = atomic.NewInt(0)
)

type Packet struct {
	data   []byte
	source net.Addr
}

// Input TODO
type Input struct {
	sync.Mutex
	udp       *udp.Server
	started   bool
	outlet    channel.Outleter
	forwarder *harvester.Forwarder
	protos    map[uint16]registry.Protocol
	C         chan Packet
}

func init() {
	err := input.Register(InputName, NewInput)
	if err != nil {
		panic(err)
	}
}

// NewInput creates a new udp input
func NewInput(
	cfg *common.Config,
	outlet channel.Connector,
	context input.Context,
) (input.Input, error) {
	logger = logp.NewLogger(InputName)
	out, err := outlet(cfg, context.DynamicFields)
	if err != nil {
		return nil, err
	}

	config := defaultConfig
	if err = cfg.Unpack(&config); err != nil {
		out.Close()
		return nil, err
	}

	input := &Input{
		outlet:    out,
		forwarder: harvester.NewForwarder(out),
		protos:    make(map[uint16]registry.Protocol, len(config.Protocols)),
	}
	for _, protoName := range config.Protocols {
		gen, err := registry.ProtocolRegistry.Get(protoName)
		if err != nil {
			out.Close()
			return nil, err
		}
		proto := gen()
		input.protos[proto.ID()] = proto
	}
	input.udp = udp.New(&config.Config, input.packetDispatch)
	return input, nil
}

func (p *Input) Publish(events []beat.Event) error {
	for _, ev := range events {
		e := util.NewData()
		e.Event = ev
		p.forwarder.Send(e)
	}
	return nil
}

// Run TODO
func (p *Input) Run() {
	p.Lock()
	defer p.Unlock()

	if !p.started {
		logger.Info("Starting UDP input")
		p.C = make(chan Packet, 819200)
		prevPackets := 0
		prevFlows := 0
		prevQueue := 0
		go func() {
			t := time.NewTicker(time.Second)
			for range t.C {
				packets := Packets.Load()
				flows := Flows.Load()
				queue := len(p.C)
				logger.Debugf("Read packets=%d flows=%d queue=%d (+%d pps +%d fps %+d qv)",
					packets, flows, queue, packets-prevPackets, flows-prevFlows, queue-prevQueue)
				prevFlows = flows
				prevPackets = packets
				prevQueue = queue
			}
		}()
		for i := 0; i < N; i++ {
			go p.recvRoutine()
		}
		err := p.udp.Start()
		if err != nil {
			logger.Errorf("Error running harvester: %v", err)
		}
		p.started = true
	}
}

// Stop stops the UDP input
func (p *Input) Stop() {
	p.Lock()
	defer p.Unlock()
	defer p.outlet.Close()
	defer close(p.C)

	logger.Info("Stopping UDP input")
	p.udp.Stop()
	p.started = false
}

// Wait suspends the UDP input
func (p *Input) Wait() {
	p.Stop()
}

func (p *Input) packetDispatch(data []byte, metadata inputsource.NetworkMetadata) {
	p.C <- Packet{data, metadata.RemoteAddr}
	Packets.Inc()
}

func (p *Input) recvRoutine() {
	for packet := range p.C {
		if len(packet.data) < 4 {
			logger.Warn("received packet too small")
			return
		}
		version := binary.BigEndian.Uint16(packet.data)

		handler, exists := p.protos[version]
		if !exists {
			logger.Warnf("Ignoring packet from version %d", version)
			return
		}
		flows := handler.OnPacket(packet.data, packet.source)
		if n := len(flows); n > 0 {
			evs := make([]beat.Event, n)
			Flows.Add(n)
			for i, flow := range flows {
				evs[i] = beat.Event{
					Timestamp: flow.Timestamp,
					Fields: common.MapStr{
						"netflow": flow.Fields,
					},
				}
			}
			p.Publish(evs)
		}
	}
}
