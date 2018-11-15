package v9

import (
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func makeAddr(t testing.TB, ipPortPair string) net.Addr {
	ip, portS, err := net.SplitHostPort(ipPortPair)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	port, err := strconv.Atoi(portS)
	if err != nil {
		t.Fatal(err)
		return nil
	}
	return &net.UDPAddr{
		IP:   net.ParseIP(ip),
		Port: port,
	}
}

func makeSessionKey(t testing.TB, ipPortPair string, sourceId uint32) SessionKey {
	return MakeSessionKey(makeAddr(t, ipPortPair), sourceId)
}

func TestSessionMap_GetOrCreate(t *testing.T) {

	t.Run("consistent behavior", func(t *testing.T) {
		sm := NewSessionMap()

		// Session is created
		s1 := sm.GetOrCreate(makeSessionKey(t, "127.0.0.1:1234", 1))
		assert.NotNil(t, s1)

		// Get a different Session for same IP different source ID
		s2 := sm.GetOrCreate(makeSessionKey(t, "127.0.0.1:1234", 2))
		assert.NotNil(t, s1)
		assert.False(t, s1 == s2)

		// Get a different Session for diff IP same source ID
		s3 := sm.GetOrCreate(makeSessionKey(t, "127.0.0.2:1234", 1))
		assert.NotNil(t, s3)
		assert.False(t, s1 == s3 || s2 == s3)

		// Get a different Session for same IP diff port, same source ID
		s4 := sm.GetOrCreate(makeSessionKey(t, "127.0.0.1:1235", 1))
		assert.NotNil(t, s4)
		assert.False(t, s1 == s4 || s2 == s4 || s3 == s4)

		// Get same Session for same params
		s1b := sm.GetOrCreate(makeSessionKey(t, "127.0.0.1:1234", 1))
		assert.NotNil(t, s1b)
		assert.True(t, s1 == s1b)
	})
	t.Run("parallel", func(t *testing.T) {
		// Goroutines should observe the same session when created in parallel
		sm := NewSessionMap()
		key := makeSessionKey(t, "127.0.0.1:9995", 42)
		const N = 8
		const Iters = 200
		C := make(chan *SessionState, N*Iters)
		wg := sync.WaitGroup{}
		wg.Add(N)
		for i := 0; i < N; i++ {
			go func() {
				last := sm.GetOrCreate(key)
				for iter := 0; iter < Iters; iter++ {
					s := sm.GetOrCreate(key)
					if last != s {
						C <- last
						last = s
					}
				}
				C <- last
				wg.Done()
			}()
		}
		wg.Wait()
		if !assert.NotEmpty(t, C) {
			return
		}
		base := <-C
		close(C)
		for s := range C {
			if !assert.True(t, s == base) {
				return
			}
		}
	})
}

func testTemplate(id uint16, creation time.Time) Template {
	return &RecordTemplate{
		ID:      id,
		Created: creation,
	}
}

func TestSessionState(t *testing.T) {
	t.Run("create and get", func(t *testing.T) {
		s := NewSession()
		baseTime := time.Now()
		t1 := testTemplate(1, baseTime)
		data := s.AddTemplate(t1)
		assert.Nil(t, data)

		t2 := s.GetTemplate(1, make([]byte, 1))
		assert.True(t, t1 == t2)
	})
	t.Run("get and create", func(t *testing.T) {
		s := NewSession()
		template := testTemplate(1, time.Now())
		data1 := []byte("hello")
		data2 := []byte("world!")
		noT := s.GetTemplate(1, data1)
		assert.Nil(t, noT)

		noT = s.GetTemplate(1, data2)
		assert.Nil(t, noT)

		stored := s.AddTemplate(template)
		if !assert.Len(t, stored, 2) {
			return
		}
		assert.Equal(t, data1, stored[0])
		assert.Equal(t, data2, stored[1])

		stored = s.AddTemplate(template)
		assert.Nil(t, stored)
	})
	t.Run("update", func(t *testing.T) {
		s := NewSession()
		baseTime := time.Now()
		t1 := testTemplate(1, baseTime)
		data := s.AddTemplate(t1)
		assert.Nil(t, data)

		t2 := testTemplate(2, baseTime)
		data = s.AddTemplate(t2)
		assert.Nil(t, data)

		t1c := s.GetTemplate(1, nil)
		assert.True(t, t1 == t1c)

		t2c := s.GetTemplate(2, nil)
		assert.True(t, t2 == t2c)

		t1b := testTemplate(1, baseTime.Add(time.Hour))
		data = s.AddTemplate(t1b)
		assert.Nil(t, data)

		t1c = s.GetTemplate(1, nil)
		assert.False(t, t1 == t1c)
		assert.True(t, t1b == t1b)
	})
}
