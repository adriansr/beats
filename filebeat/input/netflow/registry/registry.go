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

// TODO: License

package registry

import (
	"fmt"
	"net"
	"strings"

	"github.com/elastic/beats/filebeat/input/netflow/record"
)

var (
	ProtocolRegistry Registry = make(map[string]Generator)
)

type Protocol interface {
	ID() uint16
	OnPacket(data []byte, source net.Addr) []record.Record
	Start() error
	Stop() error
}

type Generator func() Protocol
type Registry map[string]Generator

func (r Registry) Register(name string, generator Generator) error {
	name = strings.ToLower(name)
	if _, exists := r[name]; exists {
		return fmt.Errorf("protocol '%s' already registered", name)
	}
	r[name] = generator
	return nil
}

func (r Registry) Get(name string) (Generator, error) {
	name = strings.ToLower(name)
	if generator, found := r[name]; found {
		return generator, nil
	}
	return nil, fmt.Errorf("protocol named '%s' not found", name)
}
