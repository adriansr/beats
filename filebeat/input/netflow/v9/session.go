package v9

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/elastic/beats/libbeat/common/atomic"
	"github.com/elastic/beats/libbeat/logp"
)

type SessionKey string

func MakeSessionKey(addr net.Addr, sourceID uint32) SessionKey {
	return SessionKey(fmt.Sprintf("%s:%d", addr, sourceID))
}

type SessionState struct {
	sync.RWMutex
	Templates map[uint16]Template
	Delete    atomic.Bool
}

func NewSession() *SessionState {
	return &SessionState{
		Templates: make(map[uint16]Template),
	}
}

func (s *SessionState) AddTemplate(t Template) {
	s.Lock()
	defer s.Unlock()
	s.Templates[t.TemplateID()] = t
}

func (s *SessionState) GetTemplate(id uint16) Template {
	s.RLock()
	defer s.RUnlock()
	template, _ := s.Templates[id]
	return template
}

type SessionMap struct {
	sync.RWMutex
	sessions map[SessionKey]*SessionState
}

func NewSessionMap() SessionMap {
	return SessionMap{
		sessions: make(map[SessionKey]*SessionState),
	}
}

func (m *SessionMap) GetOrCreate(key SessionKey) *SessionState {
	m.RLock()
	session, found := m.sessions[key]
	if found {
		session.Delete.Store(false)
	}
	m.RUnlock()
	if !found {
		m.Lock()
		if session, found = m.sessions[key]; !found {
			session = NewSession()
			m.sessions[key] = session
		}
		m.Unlock()
	}
	return session
}

func (m *SessionMap) cleanupOnce() (alive int, removed int) {
	var toDelete []SessionKey
	m.RLock()
	total := len(m.sessions)
	for key, session := range m.sessions {
		if !session.Delete.CAS(false, true) {
			toDelete = append(toDelete, key)
		} else {
		}
	}
	m.RUnlock()
	if len(toDelete) > 0 {
		m.Lock()
		total = len(m.sessions)
		for _, key := range toDelete {
			if session, found := m.sessions[key]; found && session.Delete.Load() {
				delete(m.sessions, key)
				removed++
			}
		}
		m.Unlock()
	}
	return total - removed, removed
}

func (m *SessionMap) CleanupLoop(interval time.Duration, done <-chan struct{}, logger *logp.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return

		case <-t.C:
			alive, removed := m.cleanupOnce()
			if removed > 0 {
				logger.Debugf("Expired %d sessions (%d remain)", removed, alive)
			}
		}
	}
}
