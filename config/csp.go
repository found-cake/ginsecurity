package config

import (
	"strings"

	"github.com/found-cake/ginsecurity/utils/csp"
)

type CSPConfig struct {
	Enabled         bool
	ReportOnly      bool
	DirectivesMap   map[string][]string
	CustomCSPHeader string
}

func (c *CSPConfig) initMap() {
	if c.DirectivesMap == nil {
		c.DirectivesMap = make(map[string][]string)
	}
}

func (c *CSPConfig) SetDirective(directive string, sources ...string) *CSPConfig {
	c.initMap()
	c.DirectivesMap[directive] = sources
	return c
}

func (c *CSPConfig) AddDirective(directive string, sources ...string) *CSPConfig {
	c.initMap()
	c.DirectivesMap[directive] = append(c.DirectivesMap[directive], sources...)
	return c
}

func (c *CSPConfig) RemoveDirective(directive string) *CSPConfig {
	if c.DirectivesMap != nil {
		delete(c.DirectivesMap, directive)
	}
	return c
}

func getDirectivePriority(directive string) int {
	switch directive {
	case csp.DefaultSrc:
		return 1
	case csp.ScriptSrc:
		return 2
	case csp.StyleSrc:
		return 3
	case csp.ImgSrc:
		return 4
	case csp.ConnectSrc:
		return 5
	case csp.FontSrc:
		return 6
	case csp.ObjectSrc:
		return 7
	case csp.MediaSrc:
		return 8
	case csp.FrameSrc:
		return 9
	case csp.ChildSrc:
		return 10
	case csp.FrameAncestors:
		return 11
	case csp.FormAction:
		return 12
	case csp.BaseURI:
		return 13
	case csp.ReportUri:
		return 98
	case csp.ReportTo:
		return 99
	case csp.UpgradeInsecureRequests:
		return 100
	case csp.BlockAllMixedContent:
		return 101
	default:
		return 50
	}
}

func (c *CSPConfig) GenerateHeader() string {
	if len(c.CustomCSPHeader) > 0 {
		return c.CustomCSPHeader
	}

	if len(c.DirectivesMap) == 0 {
		return ""
	}

	for directive, values := range c.DirectivesMap {
		checkMap := make(map[string]bool)
		var uniqueSources []string
		for _, value := range values {
			if _, ok := checkMap[value]; !ok {
				checkMap[value] = true
				uniqueSources = append(uniqueSources, value)
			}
		}
		c.DirectivesMap[directive] = uniqueSources
	}

	var directiveKeys []string
	for directive := range c.DirectivesMap {
		directiveKeys = append(directiveKeys, directive)
	}

	directives := make([]string, 0, len(directiveKeys))

	for len(directiveKeys) > 0 {
		lowestPriority := 999
		lowestIndex := 0

		for i, key := range directiveKeys {
			priority := getDirectivePriority(key)
			if priority < lowestPriority {
				lowestPriority = priority
				lowestIndex = i
			}
		}

		directive := directiveKeys[lowestIndex]
		sources := c.DirectivesMap[directive]

		if len(sources) > 0 {
			directives = append(directives, directive+" "+strings.Join(sources, " "))
		} else {
			directives = append(directives, directive)
		}

		directiveKeys = append(directiveKeys[:lowestIndex], directiveKeys[lowestIndex+1:]...)
	}

	return strings.Join(directives, "; ")
}

// builder
func NewCSPBuilder() *CSPConfig {
	return &CSPConfig{
		Enabled:       true,
		ReportOnly:    false,
		DirectivesMap: make(map[string][]string),
	}
}

func (c *CSPConfig) EnableReportOnly() *CSPConfig {
	c.ReportOnly = true
	return c
}

func (c *CSPConfig) DisableReportOnly() *CSPConfig {
	c.ReportOnly = false
	return c
}

// default
func DefaultCSPConfig() *CSPConfig {
	return NewCSPBuilder().
		SetDirective(csp.DefaultSrc, csp.Self).
		SetDirective(csp.ObjectSrc, csp.None)
}
