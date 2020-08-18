// +build amd64,linux

package monitoring

import (
	"sort"
	"sync"
	"sync/atomic"
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
	sync.Mutex
	traceFS  *tracing.TraceFS
	channel  *tracing.PerfChannel
	log      *logp.Logger
	close    chan struct{}
	wg       sync.WaitGroup
	syscalls map[int]string
	//stats    map[int]*auditd.Counter
	stats auditd.Stats
}

func New() auditd.Monitor {
	return &Monitor{
		log:      logp.NewLogger(logSelector),
		close:    make(chan struct{}, 1),
		syscalls: auparse.AuditSyscalls["x86_64"],
		stats: auditd.Stats{
			Counters: make(map[int]*auditd.Counter),
			Calls:    0,
			Lost:     0,
		},
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
	st := make([]*auditd.Counter, 0, len(m.stats.Counters))
	for _, v := range m.stats.Counters {
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
			atomic.AddUint64(&m.stats.Calls, 1)
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
					st.exit.end = v.Meta.Timestamp
					if st.check == 7 &&
						st.entry.start <= st.entry.end &&
						st.exit.start <= st.exit.end &&
						st.entry.end <= st.exit.start {

						timeIn := (st.entry.end - st.entry.start) + (st.exit.end - st.exit.start)
						timeOut := st.exit.end - st.entry.start

						m.Lock()
						if ct, ok := m.stats.Counters[st.syscall]; ok {
							// Update
							ct.NumCalls++
							ct.TimeIn += timeIn
							ct.TimeOut += timeOut
						} else {
							// Create
							m.stats.Counters[st.syscall] = &auditd.Counter{
								SysNo:    st.syscall,
								NumCalls: 1,
								TimeIn:   timeIn,
								TimeOut:  timeOut,
							}
						}
						m.Unlock()
					}
					delete(threads, v.Meta.TID)
					statePool.Put(st)
				}
				auditExitRetEventPool.Put(v)

			default:
				m.log.Errorf("Unknown type received via channel: %T", v)
			}

		case lost := <-m.channel.LostC():
			atomic.AddUint64(&m.stats.Lost, lost)
			m.log.Warnf("Lost %d events", lost)
			// Get rid of known state
			threads = make(map[uint32]*threadState, len(threads))

		case err := <-m.channel.ErrC():
			m.log.Warnf("Error from perf channel: %v", err)
			return err
		}
	}
}

func (m *Monitor) Stats() auditd.Stats {
	m.Lock()
	copy := make(map[int]*auditd.Counter, len(m.stats.Counters))
	calls := atomic.LoadUint64(&m.stats.Calls)
	lost := atomic.LoadUint64(&m.stats.Lost)
	for k, v := range m.stats.Counters {
		entry := *v
		copy[k] = &entry
	}
	m.Unlock()
	return auditd.Stats{
		Counters: copy,
		Calls:    calls,
		Lost:     lost,
	}
}

func (m *Monitor) Clear() {
	empty := auditd.Stats{
		Counters: make(map[int]*auditd.Counter),
		Calls:    0,
		Lost:     0,
	}
	m.Lock()
	m.stats = empty
	m.Unlock()
}
