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

// License: TODO

package netflow

import (
	"time"

	"github.com/dustin/go-humanize"
	"github.com/elastic/beats/filebeat/input/netflow/ipfix"
	"github.com/elastic/beats/filebeat/input/netflow/v1"
	"github.com/elastic/beats/filebeat/input/netflow/v5"
	"github.com/elastic/beats/filebeat/input/netflow/v9"

	"github.com/elastic/beats/filebeat/harvester"
	"github.com/elastic/beats/filebeat/inputsource/udp"
)

var defaultConfig = config{
	Config: udp.Config{
		MaxMessageSize: 64 * humanize.KiByte,
		// TODO: What should be default port?
		Host: "0.0.0.0:9995",
		// TODO: What should be the default timeout?
		// TODO: What is this timeout used for?
		Timeout: time.Minute * 5,
	},
	ForwarderConfig: harvester.ForwarderConfig{
		// TODO: Is this type=udp or type=my_input?
		Type: InputName,
	},
	Protocols: []string{v1.ProtocolName, v5.ProtocolName, v9.ProtocolName, ipfix.ProtocolName},
}

type config struct {
	udp.Config                `config:",inline"`
	harvester.ForwarderConfig `config:",inline"`
	Protocols                 []string `config:"protocols"`
}
