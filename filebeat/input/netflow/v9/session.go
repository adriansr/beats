package v9

import (
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/elastic/beats/libbeat/common/atomic"
)

type SessionKey string

func MakeSessionKey(addr net.Addr, sourceID uint32) SessionKey {
	return SessionKey(fmt.Sprintf("%s:%d", addr, sourceID))
}

type SessionState struct {
	sync.RWMutex
	Templates      map[uint16]Template
	PendingRecords map[uint16][][]byte
	Used           atomic.Bool
}

func NewSession() *SessionState {
	return &SessionState{
		Templates:      make(map[uint16]Template),
		PendingRecords: make(map[uint16][][]byte),
		Used:           atomic.MakeBool(true),
	}
}

func (s *SessionState) AddTemplate(t Template) [][]byte {
	s.Lock()
	defer s.Unlock()
	id := t.TemplateID()
	s.Templates[id] = t
	if pending, found := s.PendingRecords[id]; found {
		delete(s.PendingRecords, id)
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
	if found {
		session.Used.Store(true)
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

func (m *SessionMap) Cleanup() {
	var toDelete []SessionKey
	m.RLock()
	for key, session := range m.sessions {
		if !session.Used.Swap(false) {
			toDelete = append(toDelete, key)
		}
	}
	m.RUnlock()
	if len(toDelete) > 0 {
		m.Lock()
		for _, key := range toDelete {
			if session, found := m.sessions[key]; found && !session.Used.Load() {
				delete(m.sessions, key)
			}
		}
		m.Unlock()
	}
}

func (m *SessionMap) CleanupLoop(interval time.Duration, done <-chan struct{}) {
	t := time.NewTicker(interval)
	defer t.Stop()

	for {
		select {
		case <-done:
			return

		case <-t.C:
			m.Cleanup()
		}
	}
}
