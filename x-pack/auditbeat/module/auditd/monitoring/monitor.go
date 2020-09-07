// +build amd64,linux

package monitoring

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/pkg/errors"

	"github.com/elastic/beats/v7/auditbeat/module/auditd"
	"github.com/elastic/beats/v7/libbeat/logp"
	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing"
	"github.com/elastic/beats/v7/x-pack/auditbeat/tracing/kprobes"
	"github.com/elastic/go-libaudit/v2/auparse"
	"github.com/elastic/go-perf"
)

const (
	kprobeGroup = "ab_auditd"
	logSelector = "auditd_monitor"
)

func init() {
	auditd.SyscallMonitor.Register(New)
}

type Monitor struct {
	sync.Mutex
	engine   *kprobes.Engine
	log      *logp.Logger
	close    chan struct{}
	wg       sync.WaitGroup
	syscalls map[int]string
	stats    auditd.Stats
}

func New() auditd.Monitor {
	return &Monitor{
		log:      logp.NewLogger(logSelector),
		close:    make(chan struct{}, 1),
		syscalls: auparse.AuditSyscalls["x86_64"],
		stats: auditd.Stats{
			Counters: make(map[int32]*auditd.Counter),
			Calls:    0,
			Lost:     0,
		},
	}
}

func (m *Monitor) Start() (err error) {
	if err = m.setup(); err != nil {
		return errors.Wrap(err, "setup failed")
	}
	if err = m.engine.Start(); err != nil {
		return errors.Wrap(err, "running kprobe engine")
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
	if m.engine, err = kprobes.New(kprobeGroup,
		kprobes.WithPerfChannelConf(
			tracing.WithTID(perf.AllThreads),
			tracing.WithBufferSize(4096),
			tracing.WithErrBufferSize(1),
			tracing.WithLostBufferSize(128),
			tracing.WithRingSizeExponent(7),
		),
		kprobes.WithAutoMount(true),
		kprobes.WithLogger(m.log),
		kprobes.WithSymbolResolution("AUDIT_LOG_EXIT", []string{"audit_log_exit", "__audit_log_exit"}),
		kprobes.WithProbes(auditKprobes),
	); err != nil {
		return errors.Wrapf(err, "unable to create kprobe engine")
	}
	return m.engine.Setup()
}

func (m *Monitor) mainLoop() (err error) {
	defer func() {
		if err := m.engine.Stop(); err != nil {
			m.log.Errorf("Stopping kprobe engine: %v", err)
		}
	}()

	type threadState struct {
		syscall int32
		entry   struct {
			start, end uint64
		}
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
		case event := <-m.engine.C():
			atomic.AddUint64(&m.stats.Calls, 1)
			switch v := event.(type) {
			case *auditEntryEvent:
				st := statePool.Get().(*threadState)
				st.entry.start = v.Meta.Timestamp
				st.syscall = v.SysNO
				threads[v.Meta.TID] = st
				auditEntryEventPool.Put(v)

			case *auditEntryRetEvent:
				if st := threads[v.Meta.TID]; st != nil {
					st.entry.end = v.Meta.Timestamp
					if st.entry.start <= st.entry.end {

						timeIn := (st.entry.end - st.entry.start)
						m.Lock()
						if ct, ok := m.stats.Counters[st.syscall]; ok {
							// Update
							ct.NumCalls++
							ct.TimeIn += timeIn
						} else {
							// Create
							m.stats.Counters[st.syscall] = &auditd.Counter{
								SysNo:    st.syscall,
								NumCalls: 1,
								TimeIn:   timeIn,
							}
						}
						m.Unlock()
					}
					delete(threads, v.Meta.TID)
					statePool.Put(st)
				}
				auditEntryRetEventPool.Put(v)

			default:
				m.log.Errorf("Unknown type received via channel: %T", v)
			}

		case lost := <-m.engine.LostC():
			atomic.AddUint64(&m.stats.Lost, lost)
			m.log.Warnf("Lost %d events", lost)
			// Get rid of known state
			threads = make(map[uint32]*threadState, len(threads))

		case err := <-m.engine.ErrC():
			m.log.Warnf("Error from perf channel: %v", err)
			return err
		}
	}
}

func (m *Monitor) Stats() auditd.Stats {
	return m.clear()
}

func (m *Monitor) Clear() {
	m.clear()
}

func (m *Monitor) clear() auditd.Stats {
	empty := auditd.Stats{
		Counters: make(map[int32]*auditd.Counter),
		Calls:    0,
		Lost:     0,
	}
	m.Lock()
	saved := m.stats
	m.stats = empty
	m.Unlock()
	return saved
}
