// Licensed to Elasticsearch B.V. under one or more contributor
// license agreements. See the NOTICE file distributed with
// this work for additional information regarding copyright
// ownership. Elasticsearch B.V. licenses this file to you under
// the Apache License, Version 2.0 (the "License"); you may
// not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License.

package test

import (
	"encoding/binary"
	"net"
	"strconv"
	"testing"

	"github.com/elastic/beats/filebeat/input/netflow/record"
	"github.com/elastic/beats/libbeat/common"
	"github.com/stretchr/testify/assert"
)

func MakeAddress(t testing.TB, ipPortPair string) net.Addr {
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

func MakePacket(data []uint16) []byte {
	r := make([]byte, len(data)*2)
	for idx, val := range data {
		binary.BigEndian.PutUint16(r[idx*2:(idx+1)*2], val)
	}
	return r
}

func AssertMapEqual(t testing.TB, expected common.MapStr, actual common.MapStr) bool {
	for key, expectedValue := range expected {
		value, found := actual[key]
		if !assert.True(t, found, key) {
			return false
		}
		if !assert.Equal(t, expectedValue, value, key) {
			return false
		}
	}
	for key := range actual {
		_, found := expected[key]
		if !assert.True(t, found, key) {
			return false
		}
	}
	return true
}

func AssertRecordsEqual(t testing.TB, expected record.Record, actual record.Record) bool {
	if !assert.Equal(t, expected.Type, actual.Type) {
		return false
	}
	if !assert.Equal(t, expected.Timestamp, actual.Timestamp) {
		return false
	}
	if !AssertMapEqual(t, expected.Fields, actual.Fields) {
		return false
	}
	if !AssertMapEqual(t, expected.Exporter, actual.Exporter) {
		return false
	}
	return true
}
