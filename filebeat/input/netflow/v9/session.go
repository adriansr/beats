package v9

import (
	"net"
	"sync"
	"time"

	"github.com/elastic/beats/filebeat/input/netflow/template"
	"github.com/elastic/beats/libbeat/common/atomic"
	"github.com/elastic/beats/libbeat/logp"
)

type SessionKey string

func MakeSessionKey(addr net.Addr) SessionKey {
	return SessionKey(addr.String())
}

type TemplateKey struct {
	SourceID   uint32
	TemplateID uint16
}

type TemplateWrapper struct {
	Template template.Template
	Delete   atomic.Bool
}

type SessionState struct {
	sync.RWMutex
	Templates    map[TemplateKey]*TemplateWrapper
	lastSequence uint32
	Delete       atomic.Bool
}

func NewSession() *SessionState {
	return &SessionState{
		Templates: make(map[TemplateKey]*TemplateWrapper),
	}
}

func (s *SessionState) AddTemplate(sourceId uint32, t template.Template) {
	key := TemplateKey{sourceId, t.TemplateID()}
	s.Lock()
	defer s.Unlock()
	s.Templates[key] = &TemplateWrapper{Template: t}
}

func (s *SessionState) GetTemplate(sourceId uint32, id uint16) (template template.Template) {
	key := TemplateKey{sourceId, id}
	s.RLock()
	defer s.RUnlock()
	wrapper, found := s.Templates[key]
	if found {
		template = wrapper.Template
		wrapper.Delete.Store(false)
	}
	return template
}

func (s *SessionState) ExpireTemplates() (alive int, removed int) {
	var toDelete []TemplateKey
	s.RLock()
	for id, template := range s.Templates {
		if !template.Delete.CAS(false, true) {
			toDelete = append(toDelete, id)
		}
	}
	total := len(s.Templates)
	s.RUnlock()
	if len(toDelete) > 0 {
		s.Lock()
		total = len(s.Templates)
		for _, id := range toDelete {
			if template, found := s.Templates[id]; found && template.Delete.Load() {
				delete(s.Templates, id)
				removed++
			}
		}
		s.Unlock()
	}
	return total - removed, removed
}

func (s *SessionState) Reset() {
	s.Lock()
	defer s.Unlock()
	s.Templates = make(map[TemplateKey]*TemplateWrapper)
}

type SessionMap struct {
	sync.RWMutex
	Sessions map[SessionKey]*SessionState
}

func NewSessionMap() SessionMap {
	return SessionMap{
		Sessions: make(map[SessionKey]*SessionState),
	}
}

func (m *SessionMap) GetOrCreate(key SessionKey) *SessionState {
	m.RLock()
	session, found := m.Sessions[key]
	if found {
		session.Delete.Store(false)
	}
	m.RUnlock()
	if !found {
		m.Lock()
		if session, found = m.Sessions[key]; !found {
			session = NewSession()
			m.Sessions[key] = session
		}
		m.Unlock()
	}
	return session
}

func (m *SessionMap) cleanup() (aliveSession int, removedSession int, aliveTemplates int, removedTemplates int) {
	var toDelete []SessionKey
	m.RLock()
	total := len(m.Sessions)
	for key, session := range m.Sessions {
		a, r := session.ExpireTemplates()
		aliveTemplates += a
		removedTemplates += r
		if !session.Delete.CAS(false, true) {
			toDelete = append(toDelete, key)
		}
	}
	m.RUnlock()
	if len(toDelete) > 0 {
		m.Lock()
		total = len(m.Sessions)
		for _, key := range toDelete {
			if session, found := m.Sessions[key]; found && session.Delete.Load() {
				delete(m.Sessions, key)
				removedSession++
			}
		}
		m.Unlock()
	}
	return total - removedSession, removedSession, aliveTemplates, removedTemplates
}

func (m *SessionMap) CleanupLoop(interval time.Duration, done <-chan struct{}, logger *logp.Logger) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-done:
			return

		case <-t.C:
			aliveS, removedS, aliveT, removedT := m.cleanup()
			if removedS > 0 || removedT > 0 {
				logger.Infof("Expired %d sessions (%d remain) / %d templates (%d remain)", removedS, aliveS, removedT, aliveT)
			}
		}
	}
}
