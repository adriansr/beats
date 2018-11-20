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

type TemplateWrapper struct {
	Template Template
	Delete   atomic.Bool
}

type SessionState struct {
	sync.RWMutex
	Templates map[uint16]*TemplateWrapper
	Delete    atomic.Bool
}

func NewSession() *SessionState {
	return &SessionState{
		Templates: make(map[uint16]*TemplateWrapper),
	}
}

func (s *SessionState) AddTemplate(t Template) {
	s.Lock()
	defer s.Unlock()
	s.Templates[t.TemplateID()] = &TemplateWrapper{Template: t}
}

func (s *SessionState) GetTemplate(id uint16) (template Template) {
	s.RLock()
	defer s.RUnlock()
	wrapper, found := s.Templates[id]
	if found {
		template = wrapper.Template
		wrapper.Delete.Store(false)
	}
	return template
}

func (s *SessionState) ExpireTemplates() {
	var toDelete []uint16
	s.RLock()
	for id, template := range s.Templates {
		if !template.Delete.CAS(false, true) {
			toDelete = append(toDelete, id)
		}
	}
	s.RUnlock()
	if len(toDelete) > 0 {
		s.Lock()
		for _, id := range toDelete {
			if template, found := s.Templates[id]; found && template.Delete.Load() {
				delete(s.Templates, id)
			}
		}
		s.Unlock()
	}
}

func (s *SessionState) Reset() {
	s.Lock()
	defer s.Unlock()
	s.Templates = make(map[uint16]*TemplateWrapper)
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

func (m *SessionMap) cleanup() (alive int, removed int) {
	var toDelete []SessionKey
	m.RLock()
	total := len(m.sessions)
	for key, session := range m.sessions {
		session.ExpireTemplates()
		if !session.Delete.CAS(false, true) {
			toDelete = append(toDelete, key)
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
			alive, removed := m.cleanup()
			if removed > 0 {
				logger.Debugf("Expired %d sessions (%d remain)", removed, alive)
			}
		}
	}
}
