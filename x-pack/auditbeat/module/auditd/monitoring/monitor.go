package monitoring

import (
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/pkg/errors"

	"github.com/elastic/go-perf"

	"github.com/elastic/beats/v7/auditbeat/module/auditd"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing"
)

const (
	kprobeGroup = "ab_syscmon"
	logSelector = "auditd_monitor"
)

func init() {
	auditd.SyscallMonitor.Register(New)
}

type Monitor struct {
	traceFS  *tracing.TraceFS
	channel  *tracing.PerfChannel
	log      *logp.Logger
	close    chan struct{}
	wg       sync.WaitGroup
	syscalls map[int]string
	stats    map[key]*counters
}

type key struct {
	sysNo int
	exit  bool
}

type counters struct {
	key
	calls uint64
	time  uint64
}

func (ct counters) PerCall() time.Duration {
	return time.Duration(ct.time) / time.Duration(ct.calls)
}

func (ct counters) Print(syscalls map[int]string) string {
	dir := "exit"
	if !ct.exit {
		dir = "entry"
	}
	abs := time.Duration(ct.time)
	return fmt.Sprintf("%s:%s calls:%d totalT:%s relT:%s",
		syscalls[ct.sysNo], dir, ct.calls, abs, abs/time.Duration(ct.calls))
}

func New() auditd.Monitor {
	return &Monitor{
		log:      logp.NewLogger(logSelector),
		close:    make(chan struct{}, 1),
		syscalls: auparse.AuditSyscalls["x86_64"],
		stats:    make(map[key]*counters),
	}
}

func (m *Monitor) Start() (err error) {
	if err = m.setup(); err != nil {
		return errors.Wrap(err, "setup failed")
	}
	if err = m.channel.Run(); err != nil {
		return errors.Wrap(err, "running perf channel")
	}
	m.wg.Add(1)
	go func() {
		defer logp.Recover("crashed")
		defer m.wg.Done()
		if err = m.mainLoop(); err != nil {
			m.log.Errorf("mainLoop terminated with error: %v", err)
		} else {
			m.log.Debug("mainLoop terminated")
		}
	}()
	return nil
}

func (m *Monitor) Stop() error {
	close(m.close)
	m.wg.Wait()
	m.print()
	return nil
}

func (m *Monitor) print() {
	st := make([]*counters, 0, len(m.stats))
	for _, v := range m.stats {
		st = append(st, v)
	}
	m.log.Infof("Per-call overhead (%d syscalls)", len(st))
	sort.Slice(st, func(i, j int) bool {
		return st[i].PerCall() > st[j].PerCall()
	})
	var avg float64
	for idx, ct := range st {
		avg += float64(ct.PerCall())
		m.log.Infof("[%d] %s", idx, ct.Print(m.syscalls))
	}
	avg /= float64(len(st))
	m.log.Infof("Per-call overhead (%d syscalls) average:%s", len(st), time.Duration(avg))
	for idx, ct := range st {
		cur := float64(ct.PerCall())
		if cur < avg {
			return
		}
		mult := 100.0 * cur / avg
		m.log.Infof("[%d] %s (%.01f%%)", idx, ct.Print(m.syscalls), mult)
	}

}

func (m *Monitor) setup() (err error) {
	if m.traceFS, err = tracing.NewTraceFS(); err != nil {
		return errors.Wrap(err, "no tracefs")
	}
	if m.channel, err = tracing.NewPerfChannel(
		tracing.WithBufferSize(4096),
		tracing.WithErrBufferSize(1),
		tracing.WithLostBufferSize(128),
		tracing.WithRingSizeExponent(7),
		tracing.WithTID(perf.AllThreads),
		tracing.WithTimestamp()); err != nil {
		return errors.Wrapf(err, "unable to create perf channel")
	}

	for _, probe := range kprobes {
		if err = m.traceFS.AddKProbe(probe.Probe); err != nil {
			return errors.Wrapf(err, "failed installing kprobe '%s'", probe.Probe.String())
		}
		format, err := m.traceFS.LoadProbeFormat(probe.Probe)
		if err != nil {
			return errors.Wrapf(err, "failed loading kprobe format for '%s'", probe.Probe.String())
		}
		decoder, err := probe.Decoder(format)
		if err != nil {
			return errors.Wrapf(err, "failed creating kprobe decoder for '%s'", probe.Probe.String())
		}
		if err := m.channel.MonitorProbe(format, decoder); err != nil {
			return errors.Wrapf(err, "failed monitoring kprobe '%s'", probe.Probe.String())
		}
	}
	return nil
}

func (m *Monitor) mainLoop() (err error) {
	defer func() {
		if probes, err := m.traceFS.ListKProbes(); err == nil {
			for _, probe := range probes {
				if err := m.traceFS.RemoveKProbe(probe); err != nil {
					m.log.Errorf("Error removing kprobe '%s': %v", probe.String(), err)
				}
			}
		} else {
			m.log.Errorf("Error stopping perf channel: %v", err)
		}
	}()
	defer func() {
		if err := m.channel.Close(); err != nil {
			m.log.Errorf("Error stopping perf channel: %v", err)
		}
	}()

	type threadState struct {
		syscall     int
		entry, exit struct {
			start, end uint64
		}
		check byte
	}
	statePool := sync.Pool{
		New: func() interface{} {
			return new(threadState)
		},
	}
	threads := make(map[uint32]*threadState)

	for {
		select {
		case <-m.close:
			return nil
		case event := <-m.channel.C():
			switch v := event.(type) {
			case *auditEntryEvent:
				st := statePool.Get().(*threadState)
				st.entry.start = v.Meta.Timestamp
				st.syscall = int(v.SysNO)
				st.check = 1
				threads[v.Meta.TID] = st
				auditEntryEventPool.Put(v)

			case *auditEntryRetEvent:
				if st := threads[v.Meta.TID]; st != nil {
					st.entry.end = v.Meta.Timestamp
					st.check |= 2
				}
				auditEntryRetEventPool.Put(v)

			case *auditExitEvent:
				if st := threads[v.Meta.TID]; st != nil {
					st.exit.start = v.Meta.Timestamp
					st.check |= 4
				}
				auditExitEventPool.Put(v)

			case *auditExitRetEvent:
				if st := threads[v.Meta.TID]; st != nil {
					if st.check == 7 {
						st.exit.end = v.Meta.Timestamp
						k := key{
							sysNo: st.syscall,
							exit:  false,
						}
						if ct, ok := m.stats[k]; ok {
							ct.calls++
							ct.time += st.entry.end - st.entry.start
						} else {
							m.stats[k] = &counters{
								key:   k,
								calls: 1,
								time:  st.entry.end - st.entry.start,
							}
						}
						k.exit = true
						if ct, ok := m.stats[k]; ok {
							ct.calls++
							ct.time += st.exit.end - st.exit.start
						} else {
							m.stats[k] = &counters{
								key:   k,
								calls: 1,
								time:  st.exit.end - st.exit.start,
							}
						}
					}
					delete(threads, v.Meta.TID)
					statePool.Put(st)
				}
				auditExitRetEventPool.Put(v)

			default:
				m.log.Errorf("Unknown type received via channel: %T", v)
			}

		case lost := <-m.channel.LostC():
			m.log.Warnf("Lost %d events", lost)

		case err := <-m.channel.ErrC():
			m.log.Warnf("Error from perf channel: %v", err)
			return err
		}
	}
}
