package v9

import (
	"fmt"
	"net"
	"sync"
)

type SessionState struct {
	sync.RWMutex
	Templates      map[uint16]Template
	PendingRecords map[uint16][][]byte
}

type SessionKey string

type SessionMap struct {
	sync.Mutex
	sessions map[SessionKey]*SessionState
}

func NewSession() *SessionState {
	return &SessionState{
		Templates:      make(map[uint16]Template),
		PendingRecords: make(map[uint16][][]byte),
	}
}

func NewSessionMap() SessionMap {
	return SessionMap{
		sessions: make(map[SessionKey]*SessionState),
	}
}

func (m *SessionMap) Lookup(key SessionKey) *SessionState {
	m.Lock()
	defer m.Unlock()
	session, found := m.sessions[key]
	if !found {
		session = NewSession()
		m.sessions[key] = session
	}
	return session
}

func (s *SessionState) AddTemplate(t Template) [][]byte {
	s.Lock()
	defer s.Unlock()
	id := t.TemplateID()
	s.Templates[id] = t
	if pending, found := s.PendingRecords[id]; found {
		s.PendingRecords[id] = nil
		return pending
	}
	return nil
}

func (s *SessionState) GetTemplate(id uint16) Template {
	s.RLock()
	defer s.RUnlock()
	if template, found := s.Templates[id]; found {
		return template
	}
	return nil
}

func (s *SessionState) StorePending(id uint16, set []byte) {
	s.Lock()
	defer s.Unlock()
	s.PendingRecords[id] = append(s.PendingRecords[id], set)
}

func MakeSessionKey(addr net.Addr, sourceID uint32) SessionKey {
	return SessionKey(fmt.Sprintf("%s:%d", addr, sourceID))
}
