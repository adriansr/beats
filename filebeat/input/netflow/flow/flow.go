package flow

import (
	"time"

	"github.com/elastic/beats/libbeat/common"
)

type Flow struct {
	Timestamp time.Time
	Fields    common.MapStr
	Exporter  common.MapStr
}
