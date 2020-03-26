package cef

import (
	"strings"
	"testing"

	"gotest.tools/assert"
)

func TestTrimTrailingSpace(t *testing.T) {
	for _, tc := range []string{
		"basic ",
		" leadingtoo\t\r\n",
		"nospace",
		"Only internal space",
		"\t\r\f                \t   ",
	} {
		result := trimTrailingSpace(tc)
		expected := strings.TrimRight(tc, " \t\r\n\v\f")
		assert.Equal(t, expected, result)
	}
}
