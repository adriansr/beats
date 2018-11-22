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

package fields

//go:generate go run gen.go -skip-lines 1 -output zfields_ipfix.go -export IpfixFields --column-id=1 --column-name=2 --column-type=3 ipfix-information-elements.csv
//go:generate go run gen.go -skip-lines 1 -output zfields_cert.go -export CertFields --column-pen=2 --column-id=3 --column-name=1 --column-type=4 cert_pen6871.csv
//go:generate go run gen.go -output zfields_cisco.go -export CiscoFields --column-pen=2 --column-id=3 --column-name=1 --column-type=4 cisco.csv
