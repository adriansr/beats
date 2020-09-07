// +build amd64,linux

package monitoring

import (
	"sync"

	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing"
	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing/kprobes"
)

var auditKprobes = []kprobes.ProbeDef{
	{
		Probe: tracing.Probe{
			Type:      tracing.TypeKProbe,
			Group:     kprobeGroup,
			Name:      "entry",
			Address:   "audit_log_exit",
			Fetchargs: "sysno=+20(%di):u32",
			//Filter:    "sysno>1",
		},
		Decoder: func(desc tracing.ProbeFormat) (tracing.Decoder, error) {
			return tracing.NewStructDecoder(desc, auditEntryEventPool.Get)
		},
	},
	{
		Probe: tracing.Probe{
			Type:    tracing.TypeKRetProbe,
			Group:   kprobeGroup,
			Name:    "exit",
			Address: "audit_log_exit",
		},
		Decoder: func(desc tracing.ProbeFormat) (tracing.Decoder, error) {
			return tracing.NewStructDecoder(desc, auditEntryRetEventPool.Get)
		},
	},
}

type auditEntryEvent struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	SysNO int32            `kprobe:"sysno"`
}

var auditEntryEventPool = sync.Pool{
	New: func() interface{} {
		return new(auditEntryEvent)
	},
}

type auditEntryRetEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
}

var auditEntryRetEventPool = sync.Pool{
	New: func() interface{} {
		return new(auditEntryRetEvent)
	},
}
