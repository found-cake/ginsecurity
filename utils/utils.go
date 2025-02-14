package utils

import (
	"strings"
)

func StringsChange(values []string, changeFunc func(s string) string) []string {
	if values == nil {
		return nil
	}
	var result []string
	checkMap := make(map[string]bool)
	for _, value := range values {
		value = strings.TrimSpace(value)
		value = strings.ToLower(value)
		if _, ok := checkMap[value]; !ok {
			checkMap[value] = true
			value = changeFunc(value)
			result = append(result, value)
		}
	}
	return result
}

func InArray(arr []string, value string) bool {
	for _, v := range arr {
		if v == value {
			return true
		}
	}

	return false
}
