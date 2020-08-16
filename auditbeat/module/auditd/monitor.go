package auditd

import (
	"errors"
	"sync"
)

type Monitor interface {
	Start() error
	Stop() error
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
