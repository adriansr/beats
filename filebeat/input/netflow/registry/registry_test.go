package registry

import (
	"net"
	"testing"

	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/stretchr/testify/assert"
)

type testProto int

func (testProto) ID() uint16 {
	return 42
}

func (testProto) OnPacket([]byte, net.Addr) []record.Record {
	return nil
}

func (testProto) Start() error {
	return nil
}

func (testProto) Stop() error {
	return nil
}

func testGenerator(value int) Generator {
	return func() Protocol {
		return testProto(value)
	}
}

func TestRegistry_Register(t *testing.T) {
	t.Run("valid protocol", func(t *testing.T) {
		registry := Registry{}
		err := registry.Register("my_proto", testGenerator(0))
		assert.NoError(t, err)
	})
	t.Run("duplicate protocol", func(t *testing.T) {
		registry := Registry{}
		err := registry.Register("my_proto", testGenerator(0))
		assert.NoError(t, err)
		err = registry.Register("my_proto", testGenerator(1))
		assert.Error(t, err)
	})
}

func TestRegistry_Get(t *testing.T) {
	t.Run("valid protocol", func(t *testing.T) {
		registry := Registry{}
		err := registry.Register("my_proto", testGenerator(0))
		assert.NoError(t, err)
		gen, err := registry.Get("my_proto")
		assert.NoError(t, err)
		assert.Equal(t, testProto(0), gen())
	})
	t.Run("two protocols", func(t *testing.T) {
		registry := Registry{}
		err := registry.Register("my_proto", testGenerator(1))
		assert.NoError(t, err)
		err = registry.Register("other_proto", testGenerator(2))
		assert.NoError(t, err)
		gen, err := registry.Get("my_proto")
		assert.NoError(t, err)
		assert.Equal(t, testProto(1), gen())
		gen, err = registry.Get("other_proto")
		assert.NoError(t, err)
		assert.Equal(t, testProto(2), gen())
	})
	t.Run("not registered", func(t *testing.T) {
		registry := Registry{}
		_, err := registry.Get("my_proto")
		assert.Error(t, err)
	})
}
