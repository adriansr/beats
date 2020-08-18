package auditd

import (
	"errors"
	"fmt"
	"sync"
	"time"
)

type Monitor interface {
	Start() error
	Stop() error
	Stats() Stats
	Clear()
}

type MonitorRegistry struct {
	sync.Mutex
	constructor func() Monitor
}

var SyscallMonitor MonitorRegistry

func (reg *MonitorRegistry) Get() Monitor {
	reg.Lock()
	defer reg.Unlock()
	return reg.constructor()
}

var ErrMonitorAlreadyRegistered = errors.New("monitor already registered")

func (reg *MonitorRegistry) Register(m func() Monitor) error {
	reg.Lock()
	defer reg.Unlock()
	if reg.constructor != nil {
		return ErrMonitorAlreadyRegistered
	}
	reg.constructor = m
	return nil
}

type Stats struct {
	Counters map[int]*Counter
	Calls    uint64
	Lost     uint64
}

type Counter struct {
	SysNo    int
	NumCalls uint64
	TimeIn   uint64
	TimeOut  uint64
}

func (ct Counter) PerCall() time.Duration {
	return time.Duration(ct.TimeIn) / time.Duration(ct.NumCalls)
}

func (ct Counter) Print(syscalls map[int]string) string {
	abs := time.Duration(ct.TimeIn)
	return fmt.Sprintf("%s calls:%d totalT:%s relT:%s",
		syscalls[ct.SysNo], ct.NumCalls, abs, abs/time.Duration(ct.NumCalls))
}
