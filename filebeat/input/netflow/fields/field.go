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

import "fmt"

var Fields = FieldDict{}

type Key struct {
	EnterpriseID uint32
	FieldID      uint16
}

type Field struct {
	Name    string
	Decoder Decoder
}

type FieldDict map[Key]*Field

func RegisterFields(dict FieldDict) error {
	for key, value := range dict {
		if _, found := Fields[key]; found {
			return fmt.Errorf("field %+v is duplicated", key)
		}
		Fields[key] = value
	}
	return nil
}
