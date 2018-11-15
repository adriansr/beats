package v9

import (
	"fmt"
	"net"
	"sync"
)

type SessionKey string

func MakeSessionKey(addr net.Addr, sourceID uint32) SessionKey {
	return SessionKey(fmt.Sprintf("%s:%d", addr, sourceID))
}

type SessionState struct {
	sync.RWMutex
	Templates      map[uint16]Template
	PendingRecords map[uint16][][]byte
}

func NewSession() *SessionState {
	return &SessionState{
		Templates:      make(map[uint16]Template),
		PendingRecords: make(map[uint16][][]byte),
	}
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

func (s *SessionState) GetTemplate(id uint16, rawRecords []byte) Template {
	s.RLock()
	template, found := s.Templates[id]
	s.RUnlock()
	if !found {
		s.Lock()
		template, found = s.Templates[id]
		if !found {
			s.PendingRecords[id] = append(s.PendingRecords[id], rawRecords)
		}
		s.Unlock()
	}
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
