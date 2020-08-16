package monitoring

import (
	"sync"

	"github.com/elastic/beats/v7/x-pack/auditbeat/module/system/socket/helper"
	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing"
)

var kprobes = []helper.ProbeDef{
	{
		Probe: tracing.Probe{
			Type:      tracing.TypeKProbe,
			Group:     kprobeGroup,
			Name:      "entry_in",
			Address:   "__audit_syscall_entry",
			Fetchargs: "sysno=%di",
			Filter:    "sysno>1",
		},
		Decoder: func(desc tracing.ProbeFormat) (tracing.Decoder, error) {
			return tracing.NewStructDecoder(desc, auditEntryEventPool.Get)
		},
	},
	{
		Probe: tracing.Probe{
			Type:    tracing.TypeKRetProbe,
			Group:   kprobeGroup,
			Name:    "entry_out",
			Address: "__audit_syscall_entry",
		},
		Decoder: func(desc tracing.ProbeFormat) (tracing.Decoder, error) {
			return tracing.NewStructDecoder(desc, auditEntryRetEventPool.Get)
		},
	},
	{
		Probe: tracing.Probe{
			Type:    tracing.TypeKProbe,
			Group:   kprobeGroup,
			Name:    "exit_in",
			Address: "__audit_syscall_exit",
		},
		Decoder: func(desc tracing.ProbeFormat) (tracing.Decoder, error) {
			return tracing.NewStructDecoder(desc, auditExitEventPool.Get)
		},
	},
	{
		Probe: tracing.Probe{
			Type:    tracing.TypeKRetProbe,
			Group:   kprobeGroup,
			Name:    "exit_out",
			Address: "__audit_syscall_exit",
		},
		Decoder: func(desc tracing.ProbeFormat) (tracing.Decoder, error) {
			return tracing.NewStructDecoder(desc, auditExitRetEventPool.Get)
		},
	},
}

type auditEntryEvent struct {
	Meta  tracing.Metadata `kprobe:"metadata"`
	SysNO uintptr          `kprobe:"sysno"`
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

type auditExitEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
}

var auditExitEventPool = sync.Pool{
	New: func() interface{} {
		return new(auditExitEvent)
	},
}

type auditExitRetEvent struct {
	Meta tracing.Metadata `kprobe:"metadata"`
}

var auditExitRetEventPool = sync.Pool{
	New: func() interface{} {
		return new(auditExitRetEvent)
	},
}
