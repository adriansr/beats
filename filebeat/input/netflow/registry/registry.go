// TODO: License

package registry

import (
	"fmt"
	"strings"

	"github.com/elastic/beats/filebeat/input/netflow/flow"
	"github.com/elastic/beats/filebeat/inputsource"
)

var (
	ProtocolRegistry Registry = make(map[string]Generator)
)

type Protocol interface {
	ID() uint16
	OnPacket(data []byte, metadata inputsource.NetworkMetadata) []flow.Flow
}

type Generator func() Protocol
type Registry map[string]Generator

func (r Registry) Register(name string, generator Generator) error {
	name = strings.ToLower(name)
	if _, exists := r[name]; exists {
		return fmt.Errorf("protocol '%s' already registered", name)
	}
	r[name] = generator
	return nil
}

func (r Registry) Get(name string) (Generator, error) {
	name = strings.ToLower(name)
	if generator, found := r[name]; found {
		return generator, nil
	}
	return nil, fmt.Errorf("protocol named '%s' not found", name)
}
