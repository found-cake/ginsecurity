package utils_test

import (
	"strings"
	"testing"

	"github.com/found-cake/ginsecurity/utils"
	"github.com/stretchr/testify/assert"
)

var exmaple_list = []string{"a", "b", "c"}

func TestStringsChange(t *testing.T) {
	b := utils.StringsChange(exmaple_list, strings.ToUpper)
	assert.Equal(t, b, []string{"A", "B", "C"})
}

func TestInArray(t *testing.T) {
	assert.True(t, utils.InArray(exmaple_list, "a"))
	assert.False(t, utils.InArray(exmaple_list, "d"))
}
